<script setup lang="ts">
import axios from "axios";
import { onMounted, onUnmounted, ref, nextTick } from "vue";
import { useRouter } from "vue-router";

import { describeRequestError } from "../utils/requestError";
import { useAuthStore } from "../stores/auth";
import { LoaderCircle } from "lucide-vue-next";

type Theme = "nightshade" | "sysadmin";

interface Props {
  theme: Theme;
}

// `theme` stays declared so the shell's binding is consumed rather than
// falling through to the DOM as a stray attribute. Nothing on this page
// branches on it any more: the ring, the dot and the field follow the tokens.
defineProps<Props>();

// A lost password is replaced, not reset by token: enter the username (or
// email), and the server prints a temporary password in its console. Sign in
// with it and the app makes you choose your own. The temporary secret lives
// for 15 minutes, tops.
const router = useRouter();
const auth = useAuthStore();

const identifier = ref("");
const isSubmitting = ref(false);
const successMessage = ref<string | null>(null);
const errorMessage = ref<string | null>(null);
const showContent = ref(false);
const showStatus = ref(false);

const typedTitle = ref("");
const showCursor = ref(true);

let cursorInterval: ReturnType<typeof setInterval> | null = null;
let typingInterval: ReturnType<typeof setInterval> | null = null;

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

  cursorInterval = setInterval(() => {
    showCursor.value = !showCursor.value;
  }, 530);

  typeTitle();

  setTimeout(() => { showContent.value = true; }, 100);
  setTimeout(() => { showStatus.value = true; }, 900);
});

onUnmounted(() => {
  if (cursorInterval !== null) clearInterval(cursorInterval);
  if (typingInterval !== null) clearInterval(typingInterval);
});

async function handleIssue(): Promise<void> {
  isSubmitting.value = true;
  try {
    const { data } = await axios.post<{ message: string }>("/api/auth/forgot-password", {
      identifier: identifier.value.trim(),
    });
    successMessage.value = data.message;
    // Sessions minted under the old password are revoked server-side, so the
    // signed-in state ends here; the temporary password is used at sign-in.
    auth.setToken(null);
  } catch (error) {
    errorMessage.value = describeRequestError(
      error,
      "Could not issue a temporary password. Try again."
    );
  } finally {
    isSubmitting.value = false;
  }
}

async function handleIssueSubmit(): Promise<void> {
  errorMessage.value = null;
  successMessage.value = null;
  if (!identifier.value.trim()) {
    errorMessage.value = "Enter your username or email.";
    return;
  }
  await handleIssue();
}
</script>

<template>
  <!-- Transparent on purpose: the app-root starfield and canvas glow are the
       backdrop for every screen, this one included. -->
  <div
    class="min-h-screen flex items-center justify-center relative overflow-hidden"
  >

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
            Password Recovery
          </p>
        </div>

        <!-- One step: identifier in, temporary password printed in the console. -->
        <form class="space-y-5" @submit.prevent="handleIssueSubmit">
          <p class="text-xs text-[var(--np-text-dim)]">
            A temporary password is printed in the NetPulse console. It expires in 15 minutes.
          </p>

          <div>
            <label class="block text-xs uppercase tracking-wider mb-2 font-mono text-[var(--np-text-dim)]">
              Username or email
            </label>
            <input
              v-model="identifier"
              type="text"
              autocomplete="username"
              class="np-neon-input np-focus-glow w-full rounded-lg px-4 py-3 text-sm"
              placeholder="username or you@netpulse.local"
            />
          </div>

          <button
            type="submit"
            class="np-cyber-btn np-btn-shimmer w-full rounded-lg px-4 py-3 text-sm font-medium flex items-center justify-center gap-2"
            :disabled="isSubmitting"
          >
              <LoaderCircle v-if="isSubmitting" class="w-4 h-4 animate-spin" :stroke-width="1.7" />
            <span>{{ isSubmitting ? "Issuing…" : "Issue temporary password" }}</span>
          </button>

          <p v-if="successMessage" class="text-center text-sm text-[var(--np-accent)]">
            {{ successMessage }}
          </p>
          <p v-else-if="errorMessage" class="text-center text-sm text-red-400">{{ errorMessage }}</p>

          <button
            v-if="successMessage"
            type="button"
            @click="router.push('/login')"
            class="np-cyber-btn w-full rounded-lg px-4 py-3 text-sm font-medium"
          >
            Go to sign in
          </button>
        </form>

        <!-- Back to login -->
        <div class="mt-6 pt-5 border-t border-[var(--np-accent-border)] text-center">
          <button
            type="button"
            @click="router.push('/login')"
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
        <span class="np-status-dot" />
        <span class="text-[0.7rem] text-[var(--np-text-dim)]">NetPulse · self-hosted</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
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
@keyframes statusPulse {
  0%, 100% { box-shadow: 0 0 4px color-mix(in srgb, var(--np-accent) 30%, transparent); }
  50% { box-shadow: 0 0 14px color-mix(in srgb, var(--np-accent) 70%, transparent); }
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
