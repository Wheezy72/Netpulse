<script setup lang="ts">
import axios from "axios";
import { computed, onMounted, onUnmounted, ref, nextTick } from "vue";

type Theme = "nightshade" | "sysadmin";

interface Props {
  theme: Theme;
}

const props = defineProps<Props>();

// Step 1: enter email → receive token in server console.
// Step 2: enter token + new password → complete reset.
const step = ref<"email" | "token">("email");

const forgotEmail = ref("");
const resetToken = ref("");
const newPassword = ref("");
const confirmPassword = ref("");
const showNewPassword = ref(false);
const showConfirmPassword = ref(false);
const isSubmitting = ref(false);
const successMessage = ref<string | null>(null);
const errorMessage = ref<string | null>(null);
const showContent = ref(false);
const showStatus = ref(false);

const typedTitle = ref("");
const showCursor = ref(true);

const canvasRef = ref<HTMLCanvasElement | null>(null);
let animationId: number | null = null;
let cursorInterval: ReturnType<typeof setInterval> | null = null;
let typingInterval: ReturnType<typeof setInterval> | null = null;

const isNightshade = computed(() => props.theme === "nightshade");

const emit = defineEmits<{
  (e: "switch-to-login"): void;
  (e: "toggle-theme"): void;
}>();

interface Particle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  opacity: number;
}

function initParticles(canvas: HTMLCanvasElement): Particle[] {
  const particles: Particle[] = [];
  const count = 130;
  for (let i = 0; i < count; i++) {
    particles.push({
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      vx: (Math.random() - 0.5) * 0.5,
      vy: (Math.random() - 0.5) * 0.5,
      radius: Math.random() * 1.8 + 0.6,
      opacity: Math.random() * 0.35 + 0.1,
    });
  }
  return particles;
}

function animateCanvas() {
  const canvas = canvasRef.value;
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  let particles = initParticles(canvas);
  const connectionDist = 140;

  const accentColor = isNightshade.value
    ? { r: 20, g: 184, b: 166 }
    : { r: 245, g: 158, b: 11 };

  function draw() {
    if (!canvas || !ctx) return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    for (let i = 0; i < particles.length; i++) {
      const p = particles[i];
      p.x += p.vx;
      p.y += p.vy;

      if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
      if (p.y < 0 || p.y > canvas.height) p.vy *= -1;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${accentColor.r}, ${accentColor.g}, ${accentColor.b}, ${p.opacity})`;
      ctx.fill();

      for (let j = i + 1; j < particles.length; j++) {
        const p2 = particles[j];
        const dx = p.x - p2.x;
        const dy = p.y - p2.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < connectionDist) {
          const alpha = (1 - dist / connectionDist) * 0.15;
          ctx.beginPath();
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(p2.x, p2.y);
          ctx.strokeStyle = `rgba(${accentColor.r}, ${accentColor.g}, ${accentColor.b}, ${alpha})`;
          ctx.lineWidth = 0.6;
          ctx.stroke();
        }
      }
    }

    animationId = requestAnimationFrame(draw);
  }

  draw();
}

function handleResize() {
  const canvas = canvasRef.value;
  if (canvas) {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }
}

function typeTitle() {
  const title = "netpulse";
  let i = 0;
  typingInterval = setInterval(() => {
    if (i < title.length) {
      typedTitle.value += title[i];
      i++;
    } else {
      if (typingInterval) clearInterval(typingInterval);
      typingInterval = null;
      setTimeout(() => {
        showCursor.value = false;
        if (cursorInterval) clearInterval(cursorInterval);
        cursorInterval = null;
      }, 600);
    }
  }, 120);
}

onMounted(async () => {
  await nextTick();

  const canvas = canvasRef.value;
  if (canvas) {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    animateCanvas();
  }
  window.addEventListener("resize", handleResize);

  cursorInterval = setInterval(() => {
    showCursor.value = !showCursor.value;
  }, 530);

  typeTitle();

  setTimeout(() => { showContent.value = true; }, 100);
  setTimeout(() => { showStatus.value = true; }, 900);
});

onUnmounted(() => {
  if (animationId !== null) cancelAnimationFrame(animationId);
  if (cursorInterval !== null) clearInterval(cursorInterval);
  if (typingInterval !== null) clearInterval(typingInterval);
  window.removeEventListener("resize", handleResize);
});

async function handleEmailSubmit(): Promise<void> {
  errorMessage.value = null;
  successMessage.value = null;

  if (!forgotEmail.value.trim()) {
    errorMessage.value = "Enter your email address.";
    return;
  }

  isSubmitting.value = true;
  try {
    const { data } = await axios.post<{ message: string }>("/api/auth/forgot-password", {
      email: forgotEmail.value,
    });
    successMessage.value = data.message + " Check the server console for the reset token.";
    step.value = "token";
  } catch {
    errorMessage.value = "Could not send a reset token. Check your email and try again.";
  } finally {
    isSubmitting.value = false;
  }
}

async function handleResetSubmit(): Promise<void> {
  errorMessage.value = null;
  successMessage.value = null;

  if (!resetToken.value.trim()) {
    errorMessage.value = "Paste the reset token from the server console.";
    return;
  }
  if (newPassword.value.length < 6) {
    errorMessage.value = "Password must be at least 6 characters.";
    return;
  }
  if (newPassword.value !== confirmPassword.value) {
    errorMessage.value = "Passwords do not match.";
    return;
  }

  isSubmitting.value = true;
  try {
    const { data } = await axios.post<{ message: string }>("/api/auth/reset-password", {
      token: resetToken.value,
      new_password: newPassword.value,
    });
    successMessage.value = data.message;
    setTimeout(() => {
      emit("switch-to-login");
    }, 2000);
  } catch (e: any) {
    errorMessage.value = e.response?.data?.detail || "Reset failed. Check your token and try again.";
  } finally {
    isSubmitting.value = false;
  }
}
</script>

<template>
  <div
    class="min-h-screen flex items-center justify-center relative overflow-hidden transition-colors duration-500 bg-[#0d1117] dark:bg-[#020617]"
  >
    <canvas
      ref="canvasRef"
      class="absolute inset-0 w-full h-full"
      style="z-index: 0; pointer-events: none;"
    />

    <div
      class="np-pulse-ring"
      :class="isNightshade ? 'np-pulse-ring--nightshade' : 'np-pulse-ring--sysadmin'"
    />

    <!-- Theme toggle -->
    <button
      type="button"
      @click="emit('toggle-theme')"
      class="fixed top-4 right-4 z-50 p-2.5 rounded-lg border transition-all duration-300 hover:scale-105"
      :class="[
        isNightshade
          ? 'border-teal-400/30 bg-teal-500/10 text-teal-400 hover:bg-teal-500/20'
          : 'border-amber-400/30 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20'
      ]"
      :title="isNightshade ? 'Switch to SysAdmin' : 'Switch to Nightshade'"
    >
      <svg v-if="isNightshade" class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
      </svg>
      <svg v-else class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
      </svg>
    </button>

    <div
      class="w-full max-w-md px-4 transition-all duration-700 transform relative"
      style="z-index: 10;"
      :class="showContent ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'"
    >
      <div class="np-login-panel px-8 py-10">
        <!-- Header -->
        <div class="text-center mb-8">
          <h1 class="np-login-title text-2xl tracking-wide mb-1">
            <span>{{ typedTitle }}</span><span
              class="inline-block w-[2px] h-[1.1em] ml-[2px] align-middle"
              :class="isNightshade ? 'bg-teal-400' : 'bg-amber-400'"
              :style="{ opacity: showCursor ? 1 : 0 }"
            />
          </h1>
          <p class="text-xs font-mono" :class="isNightshade ? 'text-teal-300/50' : 'text-slate-400'">
            {{ step === "email" ? "Password Recovery" : "Set New Password" }}
          </p>
        </div>

        <!-- Step 1: Email -->
        <form v-if="step === 'email'" class="space-y-5" @submit.prevent="handleEmailSubmit">
          <p class="text-xs" :class="isNightshade ? 'text-gray-400' : 'text-slate-400'">
            Enter your account email. A one-time reset token will be printed to the server console.
          </p>

          <div>
            <label
              class="block text-xs uppercase tracking-wider mb-2 font-mono"
              :class="isNightshade ? 'text-gray-400' : 'text-slate-400'"
            >
              Email
            </label>
            <input
              v-model="forgotEmail"
              type="email"
              autocomplete="email"
              class="np-neon-input np-focus-glow w-full rounded-lg px-4 py-3 text-sm font-mono"
              placeholder="operator@netpulse.local"
            />
          </div>

          <button
            type="submit"
            class="np-cyber-btn np-btn-shimmer w-full rounded-lg px-4 py-3 text-sm font-medium flex items-center justify-center gap-2"
            :disabled="isSubmitting"
          >
            <svg v-if="isSubmitting" class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
            </svg>
            <span>{{ isSubmitting ? "Sending…" : "Send Reset Token" }}</span>
          </button>

          <p v-if="errorMessage" class="text-center text-sm text-red-400">{{ errorMessage }}</p>
        </form>

        <!-- Step 2: Token + new password -->
        <form v-else class="space-y-4" @submit.prevent="handleResetSubmit">
          <p v-if="successMessage" class="text-xs text-center" :class="isNightshade ? 'text-teal-300' : 'text-amber-300'">
            {{ successMessage }}
          </p>
          <p class="text-xs" :class="isNightshade ? 'text-gray-400' : 'text-slate-400'">
            Paste the token from the server console below and choose a new password.
          </p>

          <div>
            <label
              class="block text-xs uppercase tracking-wider mb-2 font-mono"
              :class="isNightshade ? 'text-gray-400' : 'text-slate-400'"
            >
              Reset Token
            </label>
            <input
              v-model="resetToken"
              type="text"
              autocomplete="off"
              class="np-neon-input np-focus-glow w-full rounded-lg px-4 py-3 text-sm font-mono"
              placeholder="Paste token here"
            />
          </div>

          <div>
            <label
              class="block text-xs uppercase tracking-wider mb-2 font-mono"
              :class="isNightshade ? 'text-gray-400' : 'text-slate-400'"
            >
              New Password
            </label>
            <div class="relative">
              <input
                v-model="newPassword"
                :type="showNewPassword ? 'text' : 'password'"
                autocomplete="new-password"
                class="np-neon-input np-focus-glow w-full rounded-lg px-4 py-3 pr-11 text-sm font-mono"
                placeholder="••••••••••••"
              />
              <button
                type="button"
                @click="showNewPassword = !showNewPassword"
                class="absolute inset-y-0 right-0 flex items-center px-3"
                :class="isNightshade ? 'text-teal-400/60 hover:text-teal-400' : 'text-amber-400/60 hover:text-amber-400'"
                tabindex="-1"
                :title="showNewPassword ? 'Hide password' : 'Show password'"
              >
                <svg v-if="!showNewPassword" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                </svg>
                <svg v-else class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                </svg>
              </button>
            </div>
          </div>

          <div>
            <label
              class="block text-xs uppercase tracking-wider mb-2 font-mono"
              :class="isNightshade ? 'text-gray-400' : 'text-slate-400'"
            >
              Confirm Password
            </label>
            <div class="relative">
              <input
                v-model="confirmPassword"
                :type="showConfirmPassword ? 'text' : 'password'"
                autocomplete="new-password"
                class="np-neon-input np-focus-glow w-full rounded-lg px-4 py-3 pr-11 text-sm font-mono"
                placeholder="••••••••••••"
              />
              <button
                type="button"
                @click="showConfirmPassword = !showConfirmPassword"
                class="absolute inset-y-0 right-0 flex items-center px-3"
                :class="isNightshade ? 'text-teal-400/60 hover:text-teal-400' : 'text-amber-400/60 hover:text-amber-400'"
                tabindex="-1"
                :title="showConfirmPassword ? 'Hide password' : 'Show password'"
              >
                <svg v-if="!showConfirmPassword" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                </svg>
                <svg v-else class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                </svg>
              </button>
            </div>
          </div>

          <button
            type="submit"
            class="np-cyber-btn np-btn-shimmer w-full rounded-lg px-4 py-3 text-sm font-medium flex items-center justify-center gap-2"
            :disabled="isSubmitting"
          >
            <svg v-if="isSubmitting" class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
            </svg>
            <span>{{ isSubmitting ? "Resetting…" : "Reset Password" }}</span>
          </button>

          <p v-if="errorMessage" class="text-center text-sm text-red-400">{{ errorMessage }}</p>
          <p v-if="successMessage && step === 'token'" class="text-center text-sm" :class="isNightshade ? 'text-teal-300' : 'text-amber-300'">
            {{ successMessage }}
          </p>
        </form>

        <!-- Back to login -->
        <div class="mt-6 pt-5 border-t text-center" :class="isNightshade ? 'border-teal-500/20' : 'border-amber-500/20'">
          <button
            type="button"
            @click="emit('switch-to-login')"
            class="text-sm transition-colors"
            :class="isNightshade ? 'text-teal-400 hover:text-teal-300' : 'text-amber-400 hover:text-amber-300'"
          >
            ← Back to Sign In
          </button>
        </div>
      </div>

      <!-- Status bar -->
      <div
        class="np-stagger-item mt-6 flex items-center justify-center gap-2"
        :class="showStatus ? 'np-stagger-visible' : 'np-stagger-hidden'"
      >
        <span
          class="np-status-dot"
          :class="isNightshade ? 'np-status-dot--nightshade' : 'np-status-dot--sysadmin'"
        />
        <span
          class="text-xs font-mono tracking-wider"
          :class="isNightshade ? 'text-teal-400/60' : 'text-amber-400/60'"
        >
          Secure Connection &bull; System Online
        </span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.np-pulse-ring {
  position: absolute;
  width: 420px;
  height: 420px;
  border-radius: 50%;
  pointer-events: none;
  z-index: 1;
}
.np-pulse-ring--nightshade {
  border: 1px solid rgba(20, 184, 166, 0.1);
  box-shadow: 0 0 60px rgba(20, 184, 166, 0.05), inset 0 0 60px rgba(20, 184, 166, 0.03);
  animation: pulseRingNight 4s ease-in-out infinite;
}
.np-pulse-ring--sysadmin {
  border: 1px solid rgba(245, 158, 11, 0.08);
  box-shadow: 0 0 60px rgba(245, 158, 11, 0.04), inset 0 0 60px rgba(245, 158, 11, 0.02);
  animation: pulseRingSys 4s ease-in-out infinite;
}
@keyframes pulseRingNight {
  0%, 100% { transform: scale(1); opacity: 0.4; }
  50% { transform: scale(1.08); opacity: 0.7; }
}
@keyframes pulseRingSys {
  0%, 100% { transform: scale(1); opacity: 0.3; }
  50% { transform: scale(1.06); opacity: 0.5; }
}

.np-stagger-item {
  transition: opacity 0.6s cubic-bezier(0.4, 0, 0.2, 1), transform 0.6s cubic-bezier(0.4, 0, 0.2, 1);
}
.np-stagger-hidden {
  opacity: 0;
  transform: translateY(18px);
}
.np-stagger-visible {
  opacity: 1;
  transform: translateY(0);
}

.np-status-dot {
  display: inline-block;
  width: 6px;
  height: 6px;
  border-radius: 50%;
}
.np-status-dot--nightshade {
  background: #14b8a6;
  box-shadow: 0 0 6px rgba(20, 184, 166, 0.6);
  animation: statusPulseNight 2s ease-in-out infinite;
}
.np-status-dot--sysadmin {
  background: #f59e0b;
  box-shadow: 0 0 6px rgba(245, 158, 11, 0.6);
  animation: statusPulseSys 2s ease-in-out infinite;
}
@keyframes statusPulseNight {
  0%, 100% { box-shadow: 0 0 4px rgba(20, 184, 166, 0.4); }
  50% { box-shadow: 0 0 12px rgba(20, 184, 166, 0.8); }
}
@keyframes statusPulseSys {
  0%, 100% { box-shadow: 0 0 4px rgba(245, 158, 11, 0.4); }
  50% { box-shadow: 0 0 12px rgba(245, 158, 11, 0.8); }
}

.np-focus-glow {
  transition: border-color 0.3s ease, box-shadow 0.3s ease;
}

.np-btn-shimmer {
  position: relative;
  overflow: hidden;
}
.np-btn-shimmer::after {
  content: "";
  position: absolute;
  top: 0;
  left: -100%;
  width: 100%;
  height: 100%;
  background: linear-gradient(90deg, transparent, rgba(255,255,255,0.08), transparent);
  transition: none;
}
.np-btn-shimmer:hover::after {
  animation: btnSweep 0.8s ease forwards;
}
@keyframes btnSweep {
  0% { left: -100%; }
  100% { left: 100%; }
}
</style>
