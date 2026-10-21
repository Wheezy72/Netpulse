<script setup lang="ts">
import axios from "axios";
import { computed, onMounted, onUnmounted, ref, nextTick } from "vue";

import { Eye, EyeOff, LoaderCircle, Moon, Sun } from "lucide-vue-next";

import { describeRequestError } from "../utils/requestError";

type Theme = "nightshade" | "sysadmin";

interface Props {
  theme: Theme;
}

const props = defineProps<Props>();

const username = ref("");
const email = ref("");
const password = ref("");
const confirmPassword = ref("");
const fullName = ref("");
const showPassword = ref(false);
const showConfirmPassword = ref(false);
const isSubmitting = ref(false);
const errorMessage = ref<string | null>(null);
const showContent = ref(false);

const typedTitle = ref("");
const showCursor = ref(true);
const showField0 = ref(false);
const showField1 = ref(false);
const showField2 = ref(false);
const showField3 = ref(false);
const showField4 = ref(false);
const showButton = ref(false);
const showStatus = ref(false);

const canvasRef = ref<HTMLCanvasElement | null>(null);
let animationId: number | null = null;
let cursorInterval: ReturnType<typeof setInterval> | null = null;
let typingInterval: ReturnType<typeof setInterval> | null = null;

const isNightshade = computed(() => props.theme === "nightshade");

// Particle field hue follows the active theme's accent (emerald in dark,
// indigo in light) instead of hardcoded amber/teal, so the background never
// paints a colour that belongs to the other theme.
const particleHue = computed(() => (isNightshade.value ? 158 : 243));

const emit = defineEmits<{
  (e: "register-success", token: string): void;
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

    const hue = particleHue.value;
    // The same alpha that reads as a glow on a dark surface reads as a
    // smudge on a light one, so the field is painted deeper and stronger
    // in the light theme. Without this the light pages look dead.
    const strength = isNightshade.value ? 1 : 2.1;
    const lightness = isNightshade.value ? 60 : 46;

    for (let i = 0; i < particles.length; i++) {
      const p = particles[i];
      p.x += p.vx;
      p.y += p.vy;

      if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
      if (p.y < 0 || p.y > canvas.height) p.vy *= -1;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      ctx.fillStyle = `hsla(${hue}, 75%, ${lightness}%, ${Math.min(p.opacity * strength, 0.65)})`;
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
          ctx.strokeStyle = `hsla(${hue}, 65%, 55%, ${alpha})`;
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
  setTimeout(() => { showField0.value = true; }, 300);
  setTimeout(() => { showField1.value = true; }, 400);
  setTimeout(() => { showField2.value = true; }, 550);
  setTimeout(() => { showField3.value = true; }, 700);
  setTimeout(() => { showField4.value = true; }, 850);
  setTimeout(() => { showButton.value = true; }, 1000);
  setTimeout(() => { showStatus.value = true; }, 1300);
});

onUnmounted(() => {
  if (animationId !== null) cancelAnimationFrame(animationId);
  if (cursorInterval !== null) clearInterval(cursorInterval);
  if (typingInterval !== null) clearInterval(typingInterval);
  window.removeEventListener("resize", handleResize);
});

async function handleSubmit(): Promise<void> {
  errorMessage.value = null;

  const candidateUsername = username.value.trim();
  if (!candidateUsername || !password.value) {
    errorMessage.value = "Choose a username and a password.";
    return;
  }
  if (!/^[A-Za-z0-9._-]{3,64}$/.test(candidateUsername)) {
    errorMessage.value = "Username needs 3-64 characters: letters, digits, dot, dash or underscore.";
    return;
  }
  if (password.value !== confirmPassword.value) {
    errorMessage.value = "Passwords do not match.";
    return;
  }
  if (password.value.length < 6) {
    errorMessage.value = "Password must be at least 6 characters.";
    return;
  }
  const candidateEmail = email.value.trim();
  if (candidateEmail && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(candidateEmail)) {
    errorMessage.value = "That email address does not look right.";
    return;
  }

  isSubmitting.value = true;
  try {
    await axios.post("/api/auth/users", {
      username: candidateUsername,
      email: candidateEmail || null,
      password: password.value,
      full_name: fullName.value.trim() || null,
    });

    const { data } = await axios.post<{ access_token: string; token_type: string }>(
      "/api/auth/login",
      {
        username: candidateUsername,
        password: password.value,
      }
    );
    emit("register-success", data.access_token);
  } catch (error) {
    errorMessage.value = describeRequestError(
      error,
      "Could not create the account. The username or email may already be in use."
    );
  } finally {
    isSubmitting.value = false;
  }
}
</script>

<template>
  <div
    class="min-h-screen flex items-center justify-center relative overflow-hidden transition-colors duration-500"
    :style="{ backgroundColor: 'var(--np-bg)' }"
  >
    <canvas
      ref="canvasRef"
      class="absolute inset-0 w-full h-full"
      style="z-index: 0; pointer-events: none;"
    />

    <div class="np-pulse-ring" />

    <button
      type="button"
      @click="emit('toggle-theme')"
      class="fixed top-4 right-4 z-50 p-2.5 rounded-lg border transition-all duration-300 hover:scale-105 np-brand-border np-brand-text np-brand-bg"
      :title="isNightshade ? 'Switch to light' : 'Switch to dark'"
      :aria-label="isNightshade ? 'Switch to light' : 'Switch to dark'"
    >
      <!-- The icon shows where the button takes you, not where you are. -->
      <Sun v-if="isNightshade" class="w-5 h-5" :stroke-width="1.7" />
      <Moon v-else class="w-5 h-5" :stroke-width="1.7" />
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
              :style="{ backgroundColor: 'var(--np-accent)', opacity: showCursor ? 1 : 0 }"
            />
          </h1>
          <p class="text-xs font-mono np-dim-text">
            Create account
          </p>
        </div>

        <form class="space-y-4" @submit.prevent="handleSubmit">
          <div
            class="np-stagger-item"
            :class="showField0 ? 'np-stagger-visible' : 'np-stagger-hidden'"
          >
            <label
              for="register-username"
              class="block text-xs font-medium mb-2 np-muted-text"
            >
              Username
            </label>
            <input
              id="register-username"
              v-model="username"
              type="text"
              name="username"
              autocomplete="username"
              spellcheck="false"
              class="np-neon-input np-focus-glow w-full rounded-lg px-4 py-3 text-sm"
              placeholder="admin"
            />
          </div>

          <div
            class="np-stagger-item"
            :class="showField1 ? 'np-stagger-visible' : 'np-stagger-hidden'"
          >
            <label
              for="register-name"
              class="block text-xs font-medium mb-2 np-muted-text"
            >
              Name
            </label>
            <input
              id="register-name"
              v-model="fullName"
              type="text"
              name="name"
              autocomplete="name"
              class="np-neon-input np-focus-glow w-full rounded-lg px-4 py-3 text-sm"
              placeholder="Alex Morgan"
            />
          </div>

          <div
            class="np-stagger-item"
            :class="showField2 ? 'np-stagger-visible' : 'np-stagger-hidden'"
          >
            <label
              for="register-email"
              class="block text-xs font-medium mb-2 np-muted-text"
            >
              Email <span class="normal-case opacity-70">(optional)</span>
            </label>
            <input
              id="register-email"
              v-model="email"
              type="email"
              name="email"
              autocomplete="email"
              spellcheck="false"
              class="np-neon-input np-focus-glow w-full rounded-lg px-4 py-3 text-sm"
              placeholder="you@example.com"
              aria-describedby="register-email-help"
            />
            <p id="register-email-help" class="mt-1.5 text-[0.65rem] leading-relaxed np-dim-text">
              You can add this later in Settings. It is only needed to reset a forgotten password.
            </p>
          </div>

          <div
            class="np-stagger-item"
            :class="showField3 ? 'np-stagger-visible' : 'np-stagger-hidden'"
          >
            <label
              for="register-password"
              class="block text-xs font-medium mb-2 np-muted-text"
            >
              Password
            </label>
            <div class="relative">
              <input
                id="register-password"
                v-model="password"
                :type="showPassword ? 'text' : 'password'"
                name="new-password"
                autocomplete="new-password"
                class="np-neon-input np-focus-glow w-full rounded-lg px-4 py-3 pr-11 text-sm"
                placeholder="••••••••••••"
              />
              <button
                type="button"
                @click="showPassword = !showPassword"
                class="absolute inset-y-0 right-0 flex items-center px-3 transition-opacity np-dim-text hover:np-brand-text"
                tabindex="-1"
                :title="showPassword ? 'Hide password' : 'Show password'"
              >
                <Eye v-if="!showPassword" class="w-4 h-4" :stroke-width="1.7" />
                <EyeOff v-else class="w-4 h-4" :stroke-width="1.7" />
              </button>
            </div>
          </div>

          <div
            class="np-stagger-item"
            :class="showField4 ? 'np-stagger-visible' : 'np-stagger-hidden'"
          >
            <label
              for="register-confirm"
              class="block text-xs font-medium mb-2 np-muted-text"
            >
              Confirm password
            </label>
            <div class="relative">
              <input
                id="register-confirm"
                v-model="confirmPassword"
                :type="showConfirmPassword ? 'text' : 'password'"
                name="confirm-password"
                autocomplete="new-password"
                class="np-neon-input np-focus-glow w-full rounded-lg px-4 py-3 pr-11 text-sm"
                placeholder="••••••••••••"
              />
              <button
                type="button"
                @click="showConfirmPassword = !showConfirmPassword"
                class="absolute inset-y-0 right-0 flex items-center px-3 transition-opacity np-dim-text hover:np-brand-text"
                tabindex="-1"
                :title="showConfirmPassword ? 'Hide password' : 'Show password'"
              >
                <Eye v-if="!showConfirmPassword" class="w-4 h-4" :stroke-width="1.7" />
                <EyeOff v-else class="w-4 h-4" :stroke-width="1.7" />
              </button>
            </div>
          </div>

          <div
            class="np-stagger-item"
            :class="showButton ? 'np-stagger-visible' : 'np-stagger-hidden'"
          >
            <button
              type="submit"
              class="np-primary-btn np-btn-shimmer w-full rounded-lg px-4 py-3 text-sm font-medium flex items-center justify-center gap-2"
              :disabled="isSubmitting"
            >
              <LoaderCircle v-if="isSubmitting" class="w-4 h-4 animate-spin" :stroke-width="1.7" />
              <span>{{ isSubmitting ? "Creating…" : "Create account" }}</span>
            </button>
          </div>

          <p v-if="errorMessage" class="text-center text-sm text-[var(--np-danger)]">
            {{ errorMessage }}
          </p>
        </form>

        <div class="mt-6 pt-5 border-t border-[var(--np-border-subtle)] text-center">
          <p class="text-xs mb-2 np-dim-text">
            Already have an account?
          </p>
          <button
            type="button"
            @click="emit('switch-to-login')"
            class="text-sm transition-colors np-brand-text hover:np-brand-strong"
          >
            Sign in
          </button>
        </div>
      </div>

      <div
        class="np-stagger-item mt-6 flex items-center justify-center gap-2"
        :class="showStatus ? 'np-stagger-visible' : 'np-stagger-hidden'"
      >
        <span class="np-status-dot" />
        <span class="text-xs font-mono tracking-wider np-dim-text">
          Secure connection &bull; System online
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
  border: 1px solid color-mix(in srgb, var(--np-accent) 12%, transparent);
  box-shadow: 0 0 60px color-mix(in srgb, var(--np-accent) 6%, transparent), inset 0 0 60px color-mix(in srgb, var(--np-accent) 4%, transparent);
  animation: pulseRing 4s ease-in-out infinite;
}
@keyframes pulseRing {
  0%, 100% { transform: scale(1); opacity: 0.35; }
  50% { transform: scale(1.07); opacity: 0.6; }
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
  background: var(--np-accent);
  box-shadow: 0 0 6px color-mix(in srgb, var(--np-accent) 55%, transparent);
  animation: statusPulse 2s ease-in-out infinite;
}
@keyframes statusPulse {
  0%, 100% { box-shadow: 0 0 4px color-mix(in srgb, var(--np-accent) 35%, transparent); }
  50% { box-shadow: 0 0 12px color-mix(in srgb, var(--np-accent) 75%, transparent); }
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
@media (prefers-reduced-motion: reduce) {
  .np-pulse-ring,
  .np-status-dot,
  .np-stagger-item {
    animation: none;
    transition: none;
  }
}
</style>
