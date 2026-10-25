<script setup lang="ts">
import axios from "axios";
import { computed, onMounted, onUnmounted, ref, nextTick } from "vue";

import { describeRequestError } from "../utils/requestError";
import { Eye, EyeOff, LoaderCircle } from "lucide-vue-next";

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

  function draw() {
    if (!canvas || !ctx) return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Matches the accent each theme actually paints with: emerald in the
    // dark theme, indigo in the light one. It previously used the retired
    // teal/amber pair, so this page glowed a colour nothing else used.
    const accentColor = isNightshade.value
      ? { r: 16, g: 185, b: 129 }
      : { r: 79, g: 70, b: 229 };
    // On a light surface the same alpha reads as a smudge, so the field is
    // painted stronger there to keep the page feeling alive.
    const strength = isNightshade.value ? 1 : 2.1;

    for (let i = 0; i < particles.length; i++) {
      const p = particles[i];
      p.x += p.vx;
      p.y += p.vy;

      if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
      if (p.y < 0 || p.y > canvas.height) p.vy *= -1;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${accentColor.r}, ${accentColor.g}, ${accentColor.b}, ${Math.min(p.opacity * strength, 0.65)})`;
      ctx.fill();

      for (let j = i + 1; j < particles.length; j++) {
        const p2 = particles[j];
        const dx = p.x - p2.x;
        const dy = p.y - p2.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < connectionDist) {
          const alpha = (1 - dist / connectionDist) * (isNightshade.value ? 0.15 : 0.26);
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
  // Catch a mistyped address here rather than letting the API answer 422 with
  // a generic "Validation error".
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(forgotEmail.value.trim())) {
    errorMessage.value = "That email address does not look right.";
    return;
  }

  isSubmitting.value = true;
  try {
    const { data } = await axios.post<{ message: string }>("/api/auth/forgot-password", {
      email: forgotEmail.value,
    });
    successMessage.value = data.message;
    step.value = "token";
  } catch (error) {
    errorMessage.value = describeRequestError(
      error,
      "Could not send a reset code. Check the address and try again."
    );
  } finally {
    isSubmitting.value = false;
  }
}

async function handleResetSubmit(): Promise<void> {
  errorMessage.value = null;
  successMessage.value = null;

  if (!resetToken.value.trim()) {
    errorMessage.value = "Enter the reset code.";
    return;
  }
  if (newPassword.value.length < 12) {
    errorMessage.value = "Password must be at least 12 characters.";
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
  } catch (error) {
    errorMessage.value = describeRequestError(error, "Reset failed. Check the code and try again.");
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
              :class="'bg-[var(--np-accent)]'"
              :style="{ opacity: showCursor ? 1 : 0 }"
            />
          </h1>
          <p class="text-xs text-[var(--np-text-dim)]">
            {{ step === "email" ? "Password Recovery" : "Set New Password" }}
          </p>
        </div>

        <!-- Step 1: Email -->
        <form v-if="step === 'email'" class="space-y-5" @submit.prevent="handleEmailSubmit">
          <p class="text-xs" :class="isNightshade ? 'text-gray-400' : 'text-[var(--np-text-dim)]'">
            Enter your account email. A one-time reset code is issued for the account.
          </p>

          <div>
            <label
              class="block text-xs uppercase tracking-wider mb-2 font-mono"
              :class="isNightshade ? 'text-gray-400' : 'text-[var(--np-text-dim)]'"
            >
              Email
            </label>
            <input
              v-model="forgotEmail"
              type="email"
              autocomplete="email"
              class="np-neon-input np-focus-glow w-full rounded-lg px-4 py-3 text-sm"
              placeholder="you@netpulse.local"
            />
          </div>

          <button
            type="submit"
            class="np-cyber-btn np-btn-shimmer w-full rounded-lg px-4 py-3 text-sm font-medium flex items-center justify-center gap-2"
            :disabled="isSubmitting"
          >
              <LoaderCircle v-if="isSubmitting" class="w-4 h-4 animate-spin" :stroke-width="1.7" />
            <span>{{ isSubmitting ? "Sending…" : "Send Reset Code" }}</span>
          </button>

          <p v-if="errorMessage" class="text-center text-sm text-red-400">{{ errorMessage }}</p>
        </form>

        <!-- Step 2: Token + new password -->
        <form v-else class="space-y-4" @submit.prevent="handleResetSubmit">
          <p v-if="successMessage" class="text-xs text-center text-[var(--np-accent)]">
            {{ successMessage }}
          </p>
          <p class="text-xs" :class="isNightshade ? 'text-gray-400' : 'text-[var(--np-text-dim)]'">
            Ask an administrator for the reset code, then choose a new password.
          </p>

          <div>
            <label
              class="block text-xs uppercase tracking-wider mb-2 font-mono"
              :class="isNightshade ? 'text-gray-400' : 'text-[var(--np-text-dim)]'"
            >
              Reset code
            </label>
            <input
              v-model="resetToken"
              type="text"
              autocomplete="off"
              class="np-neon-input np-focus-glow w-full rounded-lg px-4 py-3 text-sm"
              placeholder="Reset code"
            />
          </div>

          <div>
            <label
              class="block text-xs uppercase tracking-wider mb-2 font-mono"
              :class="isNightshade ? 'text-gray-400' : 'text-[var(--np-text-dim)]'"
            >
              New Password
            </label>
            <div class="relative">
              <input
                v-model="newPassword"
                :type="showNewPassword ? 'text' : 'password'"
                autocomplete="new-password"
                class="np-neon-input np-focus-glow w-full rounded-lg px-4 py-3 pr-11 text-sm"
                placeholder="••••••••••••"
              />
              <button
                type="button"
                @click="showNewPassword = !showNewPassword"
                class="absolute inset-y-0 right-0 flex items-center px-3 text-[var(--np-text-dim)] hover:text-[var(--np-accent)]"
                tabindex="-1"
                :title="showNewPassword ? 'Hide password' : 'Show password'"
              >
                <Eye v-if="!showNewPassword" class="w-4 h-4" :stroke-width="1.7" />
                <EyeOff v-else class="w-4 h-4" :stroke-width="1.7" />
              </button>
            </div>
          </div>

          <div>
            <label
              class="block text-xs uppercase tracking-wider mb-2 font-mono"
              :class="isNightshade ? 'text-gray-400' : 'text-[var(--np-text-dim)]'"
            >
              Confirm Password
            </label>
            <div class="relative">
              <input
                v-model="confirmPassword"
                :type="showConfirmPassword ? 'text' : 'password'"
                autocomplete="new-password"
                class="np-neon-input np-focus-glow w-full rounded-lg px-4 py-3 pr-11 text-sm"
                placeholder="••••••••••••"
              />
              <button
                type="button"
                @click="showConfirmPassword = !showConfirmPassword"
                class="absolute inset-y-0 right-0 flex items-center px-3 text-[var(--np-text-dim)] hover:text-[var(--np-accent)]"
                tabindex="-1"
                :title="showConfirmPassword ? 'Hide password' : 'Show password'"
              >
                <Eye v-if="!showConfirmPassword" class="w-4 h-4" :stroke-width="1.7" />
                <EyeOff v-else class="w-4 h-4" :stroke-width="1.7" />
              </button>
            </div>
          </div>

          <button
            type="submit"
            class="np-cyber-btn np-btn-shimmer w-full rounded-lg px-4 py-3 text-sm font-medium flex items-center justify-center gap-2"
            :disabled="isSubmitting"
          >
              <LoaderCircle v-if="isSubmitting" class="w-4 h-4 animate-spin" :stroke-width="1.7" />
            <span>{{ isSubmitting ? "Resetting…" : "Reset Password" }}</span>
          </button>

          <p v-if="errorMessage" class="text-center text-sm text-red-400">{{ errorMessage }}</p>
        </form>

        <!-- Back to login -->
        <div class="mt-6 pt-5 border-t border-[var(--np-accent-border)] text-center">
          <button
            type="button"
            @click="emit('switch-to-login')"
            class="text-[0.8rem] font-semibold text-[var(--np-accent)] transition-opacity hover:opacity-80"
          >
            Back to sign in
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
        <span class="text-[0.7rem] text-[var(--np-text-dim)]">NetPulse · self-hosted</span>
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
