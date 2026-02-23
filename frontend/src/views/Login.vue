<script setup lang="ts">
import axios from "axios";
import { computed, onMounted, onUnmounted, ref, nextTick } from "vue";

type Theme = "nightshade" | "sysadmin";

interface Props {
  theme: Theme;
}

const props = defineProps<Props>();

const email = ref("");
const password = ref("");
const isSubmitting = ref(false);
const errorMessage = ref<string | null>(null);
const showContent = ref(false);

const showForgotPassword = ref(false);
const forgotEmail = ref("");
const resetToken = ref("");
const newPassword = ref("");
const confirmPassword = ref("");
const forgotStep = ref<"email" | "token">("email");
const forgotMessage = ref<string | null>(null);
const forgotError = ref<string | null>(null);
const forgotLoading = ref(false);

const typedTitle = ref("");
const showCursor = ref(true);
const showField1 = ref(false);
const showField2 = ref(false);
const showButton = ref(false);
const showStatus = ref(false);
const googleEnabled = ref(false);
const googleClientId = ref("");

const canvasRef = ref<HTMLCanvasElement | null>(null);
let animationId: number | null = null;
let cursorInterval: ReturnType<typeof setInterval> | null = null;
let typingInterval: ReturnType<typeof setInterval> | null = null;

const isNightshade = computed(() => props.theme === "nightshade");

const emit = defineEmits<{
  (e: "login-success", token: string): void;
  (e: "switch-to-register"): void;
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
  const count = 45;
  for (let i = 0; i < count; i++) {
    particles.push({
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      vx: (Math.random() - 0.5) * 0.4,
      vy: (Math.random() - 0.5) * 0.4,
      radius: Math.random() * 2 + 1,
      opacity: Math.random() * 0.5 + 0.2,
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
  const connectionDist = 120;

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
  loadGoogleConfig();

  setTimeout(() => { showContent.value = true; }, 100);
  setTimeout(() => { showField1.value = true; }, 400);
  setTimeout(() => { showField2.value = true; }, 600);
  setTimeout(() => { showButton.value = true; }, 800);
  setTimeout(() => { showStatus.value = true; }, 1100);
});

onUnmounted(() => {
  if (animationId !== null) cancelAnimationFrame(animationId);
  if (cursorInterval !== null) clearInterval(cursorInterval);
  if (typingInterval !== null) clearInterval(typingInterval);
  window.removeEventListener("resize", handleResize);
});

async function loadGoogleConfig(): Promise<void> {
  try {
    const { data } = await axios.get<{ client_id: string | null; enabled: boolean }>(
      "/api/auth/google/config"
    );
    googleEnabled.value = data.enabled;
    googleClientId.value = data.client_id || "";
  } catch {
    googleEnabled.value = false;
  }
}

function handleGoogleLogin(): void {
  if (!googleClientId.value) return;
  const state = crypto.randomUUID();
  sessionStorage.setItem("np-oauth-state", state);
  const redirectUri = `${window.location.origin}/auth/google/callback`;
  const scope = encodeURIComponent("openid email profile");
  const url = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${googleClientId.value}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${scope}&state=${state}&access_type=offline&prompt=consent`;
  window.location.href = url;
}

function openForgotPassword(): void {
  showForgotPassword.value = true;
  forgotStep.value = "email";
  forgotEmail.value = "";
  resetToken.value = "";
  newPassword.value = "";
  confirmPassword.value = "";
  forgotMessage.value = null;
  forgotError.value = null;
}

function closeForgotPassword(): void {
  showForgotPassword.value = false;
}

async function handleForgotSubmit(): Promise<void> {
  forgotError.value = null;
  forgotMessage.value = null;
  if (!forgotEmail.value.trim()) {
    forgotError.value = "Enter your email address.";
    return;
  }
  forgotLoading.value = true;
  try {
    const { data } = await axios.post<{ message: string }>("/api/auth/forgot-password", {
      email: forgotEmail.value,
    });
    forgotMessage.value = data.message + " Check the server console for the reset token.";
    forgotStep.value = "token";
  } catch {
    forgotError.value = "Failed to request reset. Try again.";
  } finally {
    forgotLoading.value = false;
  }
}

async function handleResetSubmit(): Promise<void> {
  forgotError.value = null;
  forgotMessage.value = null;
  if (!resetToken.value.trim()) {
    forgotError.value = "Enter the reset token.";
    return;
  }
  if (newPassword.value.length < 6) {
    forgotError.value = "Password must be at least 6 characters.";
    return;
  }
  if (newPassword.value !== confirmPassword.value) {
    forgotError.value = "Passwords do not match.";
    return;
  }
  forgotLoading.value = true;
  try {
    const { data } = await axios.post<{ message: string }>("/api/auth/reset-password", {
      token: resetToken.value,
      new_password: newPassword.value,
    });
    forgotMessage.value = data.message;
    setTimeout(() => {
      closeForgotPassword();
    }, 2000);
  } catch (e: any) {
    forgotError.value = e.response?.data?.detail || "Reset failed. Check your token and try again.";
  } finally {
    forgotLoading.value = false;
  }
}

async function handleSubmit(): Promise<void> {
  errorMessage.value = null;

  if (!email.value || !password.value) {
    errorMessage.value = "Enter both email and password.";
    return;
  }

  isSubmitting.value = true;
  try {
    const { data } = await axios.post<{ access_token: string; token_type: string }>(
      "/api/auth/login",
      {
        email: email.value,
        password: password.value,
      }
    );
    emit("login-success", data.access_token);
  } catch {
    errorMessage.value = "Access denied. Check your credentials.";
  } finally {
    isSubmitting.value = false;
  }
}
</script>

<template>
  <div
    class="min-h-screen flex items-center justify-center relative overflow-hidden"
    :style="{ backgroundColor: 'var(--np-bg)' }"
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
        <div class="text-center mb-8">
          <h1 class="np-login-title text-2xl tracking-wide mb-1">
            <span>{{ typedTitle }}</span><span
              class="inline-block w-[2px] h-[1.1em] ml-[2px] align-middle"
              :class="isNightshade ? 'bg-teal-400' : 'bg-amber-400'"
              :style="{ opacity: showCursor ? 1 : 0 }"
            />
          </h1>
          <p class="text-xs font-mono" :class="isNightshade ? 'text-teal-300/50' : 'text-slate-400'">
            Network Operations Console
          </p>
        </div>

        <form class="space-y-5" @submit.prevent="handleSubmit">
          <div
            class="np-stagger-item"
            :class="showField1 ? 'np-stagger-visible' : 'np-stagger-hidden'"
          >
            <label
              class="block text-xs uppercase tracking-wider mb-2 font-mono"
              :class="isNightshade ? 'text-gray-400' : 'text-slate-400'"
            >
              Email
            </label>
            <input
              v-model="email"
              type="email"
              autocomplete="username"
              class="np-neon-input np-focus-glow w-full rounded-lg px-4 py-3 text-sm font-mono"
              placeholder="operator@netpulse.local"
            />
          </div>

          <div
            class="np-stagger-item"
            :class="showField2 ? 'np-stagger-visible' : 'np-stagger-hidden'"
          >
            <label
              class="block text-xs uppercase tracking-wider mb-2 font-mono"
              :class="isNightshade ? 'text-gray-400' : 'text-slate-400'"
            >
              Password
            </label>
            <input
              v-model="password"
              type="password"
              autocomplete="current-password"
              class="np-neon-input np-focus-glow w-full rounded-lg px-4 py-3 text-sm font-mono"
              placeholder="••••••••••••"
            />
          </div>

          <div
            class="np-stagger-item"
            :class="showButton ? 'np-stagger-visible' : 'np-stagger-hidden'"
          >
            <button
              type="submit"
              class="np-cyber-btn np-btn-shimmer w-full rounded-lg px-4 py-3 text-sm font-medium"
              :disabled="isSubmitting"
            >
              <span v-if="!isSubmitting">Sign In</span>
              <span v-else>Signing in...</span>
            </button>
          </div>

          <p v-if="errorMessage" class="text-center text-sm text-red-400">
            {{ errorMessage }}
          </p>

          <div class="text-center">
            <button
              type="button"
              @click="openForgotPassword"
              class="text-xs transition-colors"
              :class="isNightshade ? 'text-gray-500 hover:text-teal-400' : 'text-slate-500 hover:text-amber-400'"
            >
              Forgot password?
            </button>
          </div>
        </form>

        <div v-if="showForgotPassword" class="mt-4 space-y-3">
          <div class="border-t pt-4" :class="isNightshade ? 'border-teal-500/20' : 'border-amber-500/20'">
            <div class="flex items-center justify-between mb-3">
              <h3 class="text-xs uppercase tracking-wider font-mono" :class="isNightshade ? 'text-teal-400' : 'text-amber-400'">
                Reset Password
              </h3>
              <button
                type="button"
                @click="closeForgotPassword"
                class="text-xs transition-colors"
                :class="isNightshade ? 'text-gray-500 hover:text-teal-300' : 'text-slate-500 hover:text-amber-300'"
              >
                Cancel
              </button>
            </div>

            <div v-if="forgotStep === 'email'" class="space-y-3">
              <p class="text-xs" :class="isNightshade ? 'text-gray-400' : 'text-slate-400'">
                Enter your email to receive a reset token. The token will appear in the server console.
              </p>
              <input
                v-model="forgotEmail"
                type="email"
                placeholder="your@email.com"
                class="np-neon-input w-full rounded-lg px-4 py-2.5 text-sm font-mono"
              />
              <button
                type="button"
                @click="handleForgotSubmit"
                :disabled="forgotLoading"
                class="np-cyber-btn w-full rounded-lg px-4 py-2.5 text-sm font-medium"
              >
                {{ forgotLoading ? "Sending..." : "Request Reset Token" }}
              </button>
            </div>

            <div v-else class="space-y-3">
              <p class="text-xs" :class="isNightshade ? 'text-gray-400' : 'text-slate-400'">
                Paste the reset token from the server console and set your new password.
              </p>
              <input
                v-model="resetToken"
                type="text"
                placeholder="Paste reset token here"
                class="np-neon-input w-full rounded-lg px-4 py-2.5 text-sm font-mono"
              />
              <input
                v-model="newPassword"
                type="password"
                placeholder="New password"
                class="np-neon-input w-full rounded-lg px-4 py-2.5 text-sm font-mono"
              />
              <input
                v-model="confirmPassword"
                type="password"
                placeholder="Confirm new password"
                class="np-neon-input w-full rounded-lg px-4 py-2.5 text-sm font-mono"
              />
              <button
                type="button"
                @click="handleResetSubmit"
                :disabled="forgotLoading"
                class="np-cyber-btn w-full rounded-lg px-4 py-2.5 text-sm font-medium"
              >
                {{ forgotLoading ? "Resetting..." : "Reset Password" }}
              </button>
            </div>

            <p v-if="forgotMessage" class="text-xs text-center mt-2" :class="isNightshade ? 'text-teal-300' : 'text-amber-300'">
              {{ forgotMessage }}
            </p>
            <p v-if="forgotError" class="text-xs text-center mt-2 text-red-400">
              {{ forgotError }}
            </p>
          </div>
        </div>

        <div v-if="googleEnabled" class="mt-5">
          <div class="flex items-center gap-3 mb-4">
            <div class="flex-1 h-px" :class="isNightshade ? 'bg-teal-500/20' : 'bg-amber-500/20'" />
            <span class="text-xs font-mono" :class="isNightshade ? 'text-gray-500' : 'text-slate-500'">or</span>
            <div class="flex-1 h-px" :class="isNightshade ? 'bg-teal-500/20' : 'bg-amber-500/20'" />
          </div>
          <button
            type="button"
            @click="handleGoogleLogin"
            class="w-full flex items-center justify-center gap-3 rounded-lg px-4 py-3 text-sm font-medium border transition-all duration-300 hover:scale-[1.01]"
            :class="isNightshade
              ? 'border-teal-500/30 bg-teal-500/5 text-teal-300 hover:bg-teal-500/10 hover:border-teal-400/40'
              : 'border-amber-500/30 bg-amber-500/5 text-amber-300 hover:bg-amber-500/10 hover:border-amber-400/40'"
          >
            <svg class="w-5 h-5" viewBox="0 0 24 24">
              <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z"/>
              <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
              <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
              <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
            </svg>
            Sign in with Google
          </button>
        </div>

        <div class="mt-6 pt-5 border-t text-center" :class="isNightshade ? 'border-teal-500/20' : 'border-amber-500/20'">
          <p class="text-xs mb-2" :class="isNightshade ? 'text-gray-500' : 'text-slate-500'">
            Don't have an account?
          </p>
          <button
            type="button"
            @click="emit('switch-to-register')"
            class="text-sm transition-colors"
            :class="isNightshade ? 'text-teal-400 hover:text-teal-300' : 'text-amber-400 hover:text-amber-300'"
          >
            Create Account
          </button>
        </div>
      </div>

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
