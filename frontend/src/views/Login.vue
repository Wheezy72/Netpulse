<script setup lang="ts">
import axios from "axios";
import { useRoute, useRouter } from "vue-router";

import { Eye, EyeOff, LoaderCircle } from "lucide-vue-next";

import { describeRequestError } from "../utils/requestError";
import { computed, onMounted, onUnmounted, ref, nextTick } from "vue";

type Theme = "nightshade" | "sysadmin";

interface Props {
  theme: Theme;
}

const props = defineProps<Props>();
const router = useRouter();
const route = useRoute();

const isNightshade = computed(() => props.theme === "nightshade");

// Particle field hue follows the active theme's accent (emerald in dark,
// indigo in light) instead of hardcoded purple, so the background never
// paints a colour that belongs to the other theme.
const particleHue = computed(() => (isNightshade.value ? 158 : 243));

const username = ref("");
const password = ref("");
const showPassword = ref(false);
const rememberMe = ref(true);
const isSubmitting = ref(false);
const errorMessage = ref<string | null>(null);
// The status line used to claim "Secure Connection · System Online" whatever
// was actually true. It now asks the API, so a phone that cannot reach this
// machine is told before the first sign-in attempt fails.
const serverReachable = ref<boolean | null>(null);
// Public sign-up does not exist. Only an empty instance shows the setup link,
// and it disappears as soon as the first administrator exists. null means the
// question could not be answered yet (server unreachable), which is different
// from a confirmed "an account already exists" and must not claim one does.
const needsSetup = ref<boolean | null>(null);
const showContent = ref(false);

const typedTitle = ref("");
const showCursor = ref(true);
const showField1 = ref(false);
const showField2 = ref(false);
const showButton = ref(false);
const showStatus = ref(false);

const canvasRef = ref<HTMLCanvasElement | null>(null);
let animationId: number | null = null;
let cursorInterval: ReturnType<typeof setInterval> | null = null;
let typingInterval: ReturnType<typeof setInterval> | null = null;

const emit = defineEmits<{
  (e: "login-success", payload: { token: string; rememberMe: boolean }): void;
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
  const count = 120;
  for (let i = 0; i < count; i++) {
    particles.push({
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      vx: (Math.random() - 0.5) * 0.4,
      vy: (Math.random() - 0.5) * 0.4,
      radius: Math.random() * 1.8 + 0.5,
      opacity: Math.random() * 0.3 + 0.1,
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
  const connectionDist = 130;

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
          const alpha = (1 - dist / connectionDist) * (isNightshade.value ? 0.12 : 0.24);
          ctx.beginPath();
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(p2.x, p2.y);
          ctx.strokeStyle = `hsla(${hue}, 65%, 55%, ${alpha})`;
          ctx.lineWidth = 0.5;
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

/** Ask the API whether this instance still needs its first administrator. */
async function checkSetup(): Promise<void> {
  try {
    const { data } = await axios.get<{ needs_setup: boolean }>("/api/auth/setup-status", {
      timeout: 4000,
    });
    needsSetup.value = !!data.needs_setup;
  } catch {
    // Unknown, not "no": a failed probe used to render "Accounts are created by
    // an administrator", which told first-run users their account already
    // existed. The status line below already reports the unreachable server.
    needsSetup.value = null;
  }
}

/** Ask the API whether this machine can be reached at all. */
async function checkServer(): Promise<void> {
  try {
    await axios.get("/api/health/live", { timeout: 4000 });
    serverReachable.value = true;
    // The setup probe may have timed out while the API was still warming up;
    // ask once more now that it answers.
    if (needsSetup.value === null) void checkSetup();
  } catch {
    serverReachable.value = false;
  }
}

onMounted(async () => {
  await nextTick();

  // Arriving here because a token expired is different from a wrong password:
  // say so, otherwise the redirect looks like the app forgot the account.
  if (route.query.expired === "1") {
    errorMessage.value = "Your session expired — sign in again.";
  }

  void checkServer();
  void checkSetup();

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

async function handleSubmit(): Promise<void> {
  errorMessage.value = null;

  if (!username.value || !password.value) {
    errorMessage.value = "Enter both username and password.";
    return;
  }

  isSubmitting.value = true;
  try {
    const { data } = await axios.post<{ access_token: string; token_type: string }>(
      "/api/auth/login",
      {
        username: username.value,
        password: password.value,
        remember_me: rememberMe.value,
      }
    );
    emit("login-success", { token: data.access_token, rememberMe: rememberMe.value });
  } catch (error) {
    // An unreachable server is not a wrong password; say which one happened.
    errorMessage.value = describeRequestError(error, "That username and password don't match.");
  } finally {
    isSubmitting.value = false;
  }
}
</script>

<template>
  <div class="min-h-screen flex items-center justify-center relative overflow-hidden" :style="{ backgroundColor: 'var(--np-bg)' }">
    <canvas
      ref="canvasRef"
      class="absolute inset-0 w-full h-full"
      style="z-index: 0; pointer-events: none;"
    />

    <!-- Ambient purple glow rings -->
    <div class="np-pulse-ring" />
    <div class="np-pulse-ring np-pulse-ring--delayed" />

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
          <p class="text-xs font-mono text-[var(--np-text-muted)]">
            Network Operations Console
          </p>
        </div>

        <form class="space-y-5" @submit.prevent="handleSubmit">
          <div
            class="np-stagger-item"
            :class="showField1 ? 'np-stagger-visible' : 'np-stagger-hidden'"
          >
            <label class="block text-xs font-medium mb-2 text-[var(--np-text-muted)]">
              Username
            </label>
            <input
              v-model="username"
              type="text"
              autocomplete="username"
              class="np-neon-input w-full rounded-lg px-4 py-3 text-sm"
              placeholder="admin"
            />
          </div>

          <div
            class="np-stagger-item"
            :class="showField2 ? 'np-stagger-visible' : 'np-stagger-hidden'"
          >
            <label class="block text-xs font-medium mb-2 text-[var(--np-text-muted)]">
              Password
            </label>
            <div class="relative">
              <input
                v-model="password"
                :type="showPassword ? 'text' : 'password'"
                autocomplete="current-password"
                class="np-neon-input w-full rounded-lg px-4 py-3 pr-11 text-sm"
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

          <!-- Remember me + Forgot password row -->
          <div
            class="np-stagger-item flex items-center justify-between"
            :class="showField2 ? 'np-stagger-visible' : 'np-stagger-hidden'"
          >
            <label class="flex items-center gap-2 cursor-pointer select-none">
              <input
                v-model="rememberMe"
                type="checkbox"
                class="rounded"
                :style="{ accentColor: 'var(--np-accent)' }"
              />
              <span class="text-xs font-mono text-[var(--np-text-muted)]">
                Remember me
              </span>
            </label>
            <button
              type="button"
              @click="router.push('/forgot-password')"
              class="text-xs transition-colors np-dim-text hover:np-brand-text"
            >
              Forgot password?
            </button>
          </div>

          <div
            class="np-stagger-item"
            :class="showButton ? 'np-stagger-visible' : 'np-stagger-hidden'"
          >
            <button
              type="submit"
              class="np-login-btn w-full rounded-lg px-4 py-3 text-sm font-semibold flex items-center justify-center gap-2"
              :class="theme === 'sysadmin' ? 'np-login-btn--solid' : ''"
              :disabled="isSubmitting"
            >
              <LoaderCircle v-if="isSubmitting" class="w-4 h-4 animate-spin" :stroke-width="1.7" />
              <span>{{ isSubmitting ? "Signing in…" : "Sign In" }}</span>
            </button>
          </div>

          <p v-if="errorMessage" class="text-center text-sm text-[var(--np-danger)]">
            {{ errorMessage }}
          </p>
        </form>

        <div class="mt-6 pt-5 border-t border-[var(--np-border-subtle)] text-center">
          <template v-if="needsSetup === true">
            <p class="mb-2 text-xs text-[var(--np-text-dim)]">
              No administrator exists yet.
            </p>
            <button
              type="button"
              @click="emit('switch-to-register')"
              class="text-sm transition-colors np-brand-text hover:np-brand-strong"
            >
              Set up this instance
            </button>
          </template>
          <!-- Only a confirmed answer may claim an account exists. -->
          <p v-else-if="needsSetup === false" class="text-xs text-[var(--np-text-dim)]">
            Accounts are created by an administrator in Settings → Users.
          </p>
        </div>
      </div>

      <div
        class="np-stagger-item mt-6 flex items-center justify-center gap-2"
        :class="showStatus ? 'np-stagger-visible' : 'np-stagger-hidden'"
      >
        <span class="np-status-dot" :class="serverReachable === false ? 'np-status-dot--down' : ''" />
        <span class="text-[0.7rem] np-dim-text">
          {{
            serverReachable === null
              ? 'Checking the server…'
              : serverReachable
                ? 'Server reachable'
                : 'Cannot reach the server'
          }}
        </span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.np-pulse-ring {
  position: absolute;
  width: 400px;
  height: 400px;
  border-radius: 50%;
  pointer-events: none;
  z-index: 1;
  border: 1px solid color-mix(in srgb, var(--np-accent) 12%, transparent);
  box-shadow: 0 0 60px color-mix(in srgb, var(--np-accent) 6%, transparent), inset 0 0 60px color-mix(in srgb, var(--np-accent) 4%, transparent);
  animation: pulseRing 5s ease-in-out infinite;
}
.np-pulse-ring--delayed {
  width: 550px;
  height: 550px;
  animation-delay: 2s;
  opacity: 0.5;
}
@keyframes pulseRing {
  0%, 100% { transform: scale(1); opacity: 0.3; }
  50% { transform: scale(1.06); opacity: 0.6; }
}

.np-login-btn {
  background: color-mix(in srgb, var(--np-accent) 18%, transparent);
  border: 1px solid color-mix(in srgb, var(--np-accent) 45%, transparent);
  color: var(--np-accent-strong);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  transition: background-color 0.3s ease, border-color 0.3s ease, color 0.3s ease;
  position: relative;
  overflow: hidden;
}
/* Light theme: a pale indigo pill with indigo type reads as disabled.
   A solid accent fill makes the primary action unmistakable. */
.np-login-btn--solid {
  background: var(--np-accent);
  border-color: var(--np-accent);
  color: #ffffff;
  box-shadow: 0 6px 18px color-mix(in srgb, var(--np-accent) 22%, transparent);
}
.np-login-btn--solid:hover {
  background: var(--np-accent-strong);
  border-color: var(--np-accent-strong);
}

.np-login-btn:hover {
  background: color-mix(in srgb, var(--np-accent) 30%, transparent);
  border-color: color-mix(in srgb, var(--np-accent) 65%, transparent);
  box-shadow: 0 0 30px color-mix(in srgb, var(--np-accent) 25%, transparent);
}
.np-login-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.np-login-btn::after {
  content: "";
  position: absolute;
  top: 0;
  left: -100%;
  width: 100%;
  height: 100%;
  background: linear-gradient(90deg, transparent, rgba(255,255,255,0.06), transparent);
}
.np-login-btn:hover::after {
  animation: btnSweep 0.8s ease forwards;
}
@keyframes btnSweep {
  0% { left: -100%; }
  100% { left: 100%; }
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
  box-shadow: 0 0 8px color-mix(in srgb, var(--np-accent) 50%, transparent);
  animation: statusPulse 2s ease-in-out infinite;
}

/* Unreachable: stop pulsing, because nothing is there to answer. */
.np-status-dot--down {
  background: var(--np-danger);
  box-shadow: 0 0 8px color-mix(in srgb, var(--np-danger) 50%, transparent);
  animation: none;
}
@keyframes statusPulse {
  0%, 100% { box-shadow: 0 0 4px color-mix(in srgb, var(--np-accent) 30%, transparent); }
  50% { box-shadow: 0 0 14px color-mix(in srgb, var(--np-accent) 70%, transparent); }
}
</style>
