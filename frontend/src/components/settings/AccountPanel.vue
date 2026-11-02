<script setup lang="ts">
/**
 * Account self-service: attach an email address and change the password.
 *
 * Sits in Settings as its own tab. Both actions talk to /api/auth/me (PATCH)
 * and /api/auth/change-password; errors are rendered inline next to the field
 * that caused them rather than as global toasts.
 */
import axios from "axios";
import { computed, onMounted, ref } from "vue";
import { useRouter } from "vue-router";

import { useAuthStore } from "../../stores/auth";
import { describeRequestError } from "../../utils/requestError";

const router = useRouter();

/**
 * Escape hatch for "I don't remember my current password". Requiring the old
 * password is the right default (an unattended console must not hand its
 * session away), but a user who forgot it had nowhere to go from this screen:
 * the reset flow needs no old password, and this link walks to it.
 */
function goToRecovery(): void {
  router.push("/forgot-password");
}

const auth = useAuthStore();

// --- Email ------------------------------------------------------------------
const email = ref("");
const emailSaving = ref(false);
const emailMessage = ref<string | null>(null);
const emailError = ref<string | null>(null);

const currentEmail = computed(() => auth.user?.email ?? "");
const hasEmail = computed(() => !!currentEmail.value);

/**
 * The "on file" hint sits next to a field the user is actively retyping, so
 * it only needs to confirm *which* address is there. Standard practice
 * (GitHub, AWS, Google) is to show the first character and the domain with
 * the local part masked — enough to recognise, useless to a shoulder
 * surfer or a screen share.
 */
const maskedEmail = computed(() => {
  const value = currentEmail.value;
  const at = value.indexOf("@");
  if (at < 1) return value;
  return `${value[0]}\u2022\u2022\u2022\u2022${value.slice(at)}`;
});

async function saveEmail(): Promise<void> {
  emailError.value = null;
  emailMessage.value = null;
  const candidate = email.value.trim();
  if (!candidate) {
    emailError.value = "Enter an email address.";
    return;
  }

  emailSaving.value = true;
  try {
    const { data } = await axios.patch<{ user: any; access_token: string | null }>("/api/auth/me", {
      email: candidate,
    });
    // The email is the token subject, so the backend hands back a fresh token.
    if (data.access_token) auth.setToken(data.access_token);
    if (data.user) auth.user = data.user;
    email.value = "";
    emailMessage.value = hasEmail.value
      ? "Email updated. Password recovery is now available."
      : "Email saved.";
  } catch (error) {
    emailError.value = describeRequestError(error, "Could not save that email address.");
  } finally {
    emailSaving.value = false;
  }
}

// --- Password ---------------------------------------------------------------
const currentPassword = ref("");
const newPassword = ref("");
const confirmPassword = ref("");
const passwordSaving = ref(false);
const passwordMessage = ref<string | null>(null);
const passwordError = ref<string | null>(null);

async function changePassword(): Promise<void> {
  passwordError.value = null;
  passwordMessage.value = null;

  if (!currentPassword.value || !newPassword.value) {
    passwordError.value = "Fill in both password fields.";
    return;
  }
  if (newPassword.value.length < 12) {
    passwordError.value = "New password must be at least 12 characters.";
    return;
  }
  if (newPassword.value !== confirmPassword.value) {
    passwordError.value = "The two new passwords do not match.";
    return;
  }

  passwordSaving.value = true;
  try {
    const { data } = await axios.post<{ access_token?: string }>("/api/auth/change-password", {
      current_password: currentPassword.value,
      new_password: newPassword.value,
    });
    // The change bumps the account's session version, which invalidates this
    // device's token along with every other one. The backend hands back a fresh
    // token so "you stay signed in on this device" remains true.
    if (data.access_token) auth.setToken(data.access_token);
    currentPassword.value = "";
    newPassword.value = "";
    confirmPassword.value = "";
    passwordMessage.value = "Password updated.";
  } catch (error) {
    passwordError.value = describeRequestError(error, "Could not update the password.");
  } finally {
    passwordSaving.value = false;
  }
}

// --- Sessions ---------------------------------------------------------------
const sessionsSaving = ref(false);
const sessionsError = ref<string | null>(null);

/**
 * Revoke every token for this account.
 *
 * The request itself is made with the token being revoked, so the local copy is
 * cleared and the user returned to the sign-in screen instead of being left on
 * a page whose next request is guaranteed to 401.
 */
async function signOutEverywhere(): Promise<void> {
  sessionsSaving.value = true;
  sessionsError.value = null;
  try {
    await axios.post("/api/auth/logout-all");
    auth.setToken(null);
    await router.push("/login");
  } catch (error) {
    sessionsError.value = describeRequestError(error, "Could not revoke the sessions.");
  } finally {
    sessionsSaving.value = false;
  }
}

// --- Two-factor authentication ---------------------------------------------
const mfaEnabled = ref(false);
const mfaRemaining = ref(0);
const mfaPassword = ref("");
const mfaCode = ref("");
const mfaSecret = ref("");
const mfaUri = ref("");
const recoveryCodes = ref<string[]>([]);
const mfaBusy = ref(false);
const mfaError = ref<string | null>(null);
const mfaMessage = ref<string | null>(null);

function resetMfaMessages(): void {
  mfaError.value = null;
  mfaMessage.value = null;
}

async function loadMfaStatus(): Promise<void> {
  try {
    const { data } = await axios.get<{ enabled: boolean; recovery_codes_remaining: number }>(
      "/api/auth/mfa/status"
    );
    mfaEnabled.value = !!data.enabled;
    mfaRemaining.value = data.recovery_codes_remaining || 0;
  } catch {
    // The section keeps its default state; the rest of the panel works.
  }
}

async function beginMfa(): Promise<void> {
  resetMfaMessages();
  if (!mfaPassword.value) {
    mfaError.value = "Enter your password to start enrolment.";
    return;
  }
  mfaBusy.value = true;
  try {
    const { data } = await axios.post<{ secret: string; otpauth_uri: string }>(
      "/api/auth/mfa/setup",
      { password: mfaPassword.value }
    );
    mfaSecret.value = data.secret;
    mfaUri.value = data.otpauth_uri;
    recoveryCodes.value = [];
    mfaMessage.value = "Add that key to your authenticator app, then enter the code it shows.";
  } catch (error) {
    mfaError.value = describeRequestError(error, "Could not start enrolment.");
  } finally {
    mfaBusy.value = false;
  }
}

async function confirmMfa(): Promise<void> {
  resetMfaMessages();
  if (!mfaCode.value.trim()) {
    mfaError.value = "Enter the code from your authenticator app.";
    return;
  }
  mfaBusy.value = true;
  try {
    const { data } = await axios.post<{ enabled: boolean; recovery_codes: string[] }>(
      "/api/auth/mfa/enable",
      { code: mfaCode.value }
    );
    mfaEnabled.value = true;
    recoveryCodes.value = data.recovery_codes || [];
    mfaRemaining.value = recoveryCodes.value.length;
    mfaSecret.value = "";
    mfaUri.value = "";
    mfaCode.value = "";
    mfaPassword.value = "";
    mfaMessage.value =
      "Two-factor authentication is on. Save these recovery codes now — they are shown once.";
  } catch (error) {
    mfaError.value = describeRequestError(error, "That code was not accepted.");
  } finally {
    mfaBusy.value = false;
  }
}

async function disableMfa(): Promise<void> {
  resetMfaMessages();
  if (!mfaPassword.value || !mfaCode.value.trim()) {
    mfaError.value = "Your password and a current code are both required.";
    return;
  }
  mfaBusy.value = true;
  try {
    await axios.post("/api/auth/mfa/disable", {
      password: mfaPassword.value,
      code: mfaCode.value,
    });
    mfaEnabled.value = false;
    mfaRemaining.value = 0;
    recoveryCodes.value = [];
    mfaPassword.value = "";
    mfaCode.value = "";
    mfaMessage.value = "Two-factor authentication is off.";
  } catch (error) {
    mfaError.value = describeRequestError(error, "Could not turn it off.");
  } finally {
    mfaBusy.value = false;
  }
}

onMounted(async () => {
  if (!auth.user) await auth.loadUser();
  await loadMfaStatus();
});
</script>

<template>
  <section class="np-panel p-4 space-y-6">
    <header class="np-panel-header -mx-4 -mt-4 mb-4 px-4">
      <div class="flex flex-col">
        <span class="np-panel-title">Account</span>
        <span class="text-[0.7rem] text-[var(--np-text-dim)]">
          Your own sign-in details. These apply to this account only.
        </span>
      </div>
    </header>

    <!-- Email ------------------------------------------------------------->
    <div class="np-settings-section space-y-3">
      <div>
        <p class="np-settings-section-title">Email address</p>
        <p class="text-[0.7rem] text-[var(--np-text-dim)]">
          Password recovery needs an address on file. You can add or change it here at any time.
        </p>
      </div>

      <div class="flex flex-col gap-1">
        <label for="account-email" class="text-[0.7rem] font-semibold text-[var(--np-text-muted)]">
          Email
        </label>
        <div class="flex flex-wrap items-center gap-2">
          <input
            id="account-email"
            v-model="email"
            type="email"
            name="email"
            autocomplete="email"
            spellcheck="false"
            class="np-neon-input min-w-0 flex-1 rounded px-3 py-2 text-[0.8rem]"
            :placeholder="hasEmail ? '' : 'you@example.com'"
            :aria-invalid="!!emailError"
            aria-describedby="account-email-help"
            @keyup.enter="saveEmail"
          />
          <button
            type="button"
            class="np-cyber-btn np-cyber-btn--solid px-4 py-2 text-[0.7rem]"
            :disabled="emailSaving"
            @click="saveEmail"
          >
            {{ emailSaving ? "Saving…" : hasEmail ? "Update email" : "Add email" }}
          </button>
        </div>
        <p id="account-email-help" class="text-[0.7rem] text-[var(--np-text-dim)]">
          <template v-if="hasEmail">Currently on file: <span class="font-mono" :title="currentEmail">{{ maskedEmail }}</span></template>
          <template v-else>No email on file. Password recovery is unavailable until you add one.</template>
        </p>
        <p v-if="emailError" class="text-[0.7rem] font-semibold text-[var(--np-danger)]">{{ emailError }}</p>
        <p v-else-if="emailMessage" class="text-[0.7rem] font-semibold text-[var(--np-success)]">{{ emailMessage }}</p>
      </div>
    </div>

    <!-- Password ---------------------------------------------------------->
    <div class="np-settings-section space-y-3">
      <div>
        <p class="np-settings-section-title">Password</p>
        <p class="text-[0.7rem] text-[var(--np-text-dim)]">
          Use at least 12 characters. You stay signed in on this device after the change.
        </p>
      </div>

      <div class="grid gap-3 md:grid-cols-3">
        <div class="flex flex-col gap-1">
          <label for="current-password" class="text-[0.7rem] font-semibold text-[var(--np-text-muted)]">
            Current password
          </label>
          <input
            id="current-password"
            v-model="currentPassword"
            type="password"
            name="current-password"
            autocomplete="current-password"
            class="np-neon-input rounded px-3 py-2 text-[0.8rem]"
          />
        </div>
        <div class="flex flex-col gap-1">
          <label for="new-password" class="text-[0.7rem] font-semibold text-[var(--np-text-muted)]">
            New password
          </label>
          <input
            id="new-password"
            v-model="newPassword"
            type="password"
            name="new-password"
            autocomplete="new-password"
            class="np-neon-input rounded px-3 py-2 text-[0.8rem]"
            :aria-invalid="!!passwordError"
            aria-describedby="account-password-help"
          />
        </div>
        <div class="flex flex-col gap-1">
          <label for="confirm-password" class="text-[0.7rem] font-semibold text-[var(--np-text-muted)]">
            Confirm new password
          </label>
          <input
            id="confirm-password"
            v-model="confirmPassword"
            type="password"
            name="confirm-password"
            autocomplete="new-password"
            class="np-neon-input rounded px-3 py-2 text-[0.8rem]"
            @keyup.enter="changePassword"
          />
        </div>
      </div>

      <div class="flex flex-wrap items-center justify-between gap-3">
        <div id="account-password-help" class="flex flex-wrap items-center gap-x-3 gap-y-1 text-[0.7rem] text-[var(--np-text-dim)]">
          <span>Changing it signs out every other session; this device stays in.</span>
          <button
            type="button"
            class="font-semibold text-[var(--np-accent)] underline underline-offset-2 transition-opacity hover:opacity-80"
            @click="goToRecovery"
          >
            Forgot the current password?
          </button>
        </div>
        <button
          type="button"
          class="np-cyber-btn px-4 py-2 text-[0.7rem]"
          :disabled="passwordSaving"
          @click="changePassword"
        >
          {{ passwordSaving ? "Updating…" : "Change password" }}
        </button>
      </div>
      <p v-if="passwordError" class="text-[0.7rem] font-semibold text-[var(--np-danger)]">{{ passwordError }}</p>
      <p v-else-if="passwordMessage" class="text-[0.7rem] font-semibold text-[var(--np-success)]">{{ passwordMessage }}</p>
    </div>

    <!-- Two-factor -------------------------------------------------------->
    <div class="np-settings-section space-y-3">
      <div>
        <p class="np-settings-section-title">Two-factor authentication</p>
        <p class="text-[0.7rem] text-[var(--np-text-dim)]">
          A code from your phone on top of your password. This is what keeps a
          leaked password from opening the console on its own.
        </p>
      </div>

      <p v-if="mfaEnabled" class="text-[0.7rem] font-semibold text-[var(--np-success)]">
        Enabled<template v-if="mfaRemaining">
          · {{ mfaRemaining }} recovery code{{ mfaRemaining === 1 ? "" : "s" }} left
        </template>
      </p>

      <div class="grid gap-3 md:grid-cols-2">
        <div class="flex flex-col gap-1">
          <label for="mfa-password" class="text-[0.7rem] font-semibold text-[var(--np-text-muted)]">
            Your password
          </label>
          <input
            id="mfa-password"
            v-model="mfaPassword"
            type="password"
            autocomplete="current-password"
            class="np-neon-input rounded px-3 py-2 text-[0.8rem]"
          />
        </div>
        <div class="flex flex-col gap-1">
          <label for="mfa-code" class="text-[0.7rem] font-semibold text-[var(--np-text-muted)]">
            {{ mfaEnabled ? "Current code" : "Code from the app" }}
          </label>
          <input
            id="mfa-code"
            v-model="mfaCode"
            inputmode="numeric"
            autocomplete="one-time-code"
            class="np-neon-input rounded px-3 py-2 text-[0.8rem]"
            placeholder="123 456"
            @keyup.enter="mfaEnabled ? disableMfa() : confirmMfa()"
          />
        </div>
      </div>

      <div v-if="mfaSecret" class="space-y-2 rounded border border-[var(--np-border-subtle)] p-3">
        <p class="text-[0.7rem] text-[var(--np-text-dim)]">Manual setup key</p>
        <p class="break-all font-mono text-[0.8rem]">{{ mfaSecret }}</p>
        <p class="break-all text-[0.7rem] text-[var(--np-text-dim)]">{{ mfaUri }}</p>
      </div>

      <div v-if="recoveryCodes.length" class="space-y-1 rounded border border-[var(--np-accent-border)] p-3">
        <p class="text-[0.7rem] font-semibold text-[var(--np-text-muted)]">
          Recovery codes — shown once
        </p>
        <div class="grid grid-cols-2 gap-1 font-mono text-[0.8rem]">
          <span v-for="code in recoveryCodes" :key="code">{{ code }}</span>
        </div>
      </div>

      <div class="flex flex-wrap items-center gap-2">
        <button
          v-if="!mfaEnabled && !mfaSecret"
          type="button"
          class="np-cyber-btn px-4 py-2 text-[0.7rem]"
          :disabled="mfaBusy"
          @click="beginMfa"
        >
          Start setup
        </button>
        <button
          v-if="!mfaEnabled && mfaSecret"
          type="button"
          class="np-cyber-btn np-cyber-btn--solid px-4 py-2 text-[0.7rem]"
          :disabled="mfaBusy"
          @click="confirmMfa"
        >
          Turn on
        </button>
        <button
          v-if="mfaEnabled"
          type="button"
          class="np-cyber-btn px-4 py-2 text-[0.7rem]"
          :disabled="mfaBusy"
          @click="disableMfa"
        >
          Turn off
        </button>
      </div>

      <p v-if="mfaError" class="text-[0.7rem] font-semibold text-[var(--np-danger)]">{{ mfaError }}</p>
      <p v-else-if="mfaMessage" class="text-[0.7rem] font-semibold text-[var(--np-success)]">
        {{ mfaMessage }}
      </p>
    </div>

    <!-- Sessions ---------------------------------------------------------->
    <div class="np-settings-section space-y-3">
      <div>
        <p class="np-settings-section-title">Sessions</p>
        <p class="text-[0.7rem] text-[var(--np-text-dim)]">
          Every sign-in holds a token until it expires. Signing out everywhere invalidates all of
          them at once, including one on a device you no longer control.
        </p>
      </div>

      <button
        type="button"
        class="np-cyber-btn px-4 py-2 text-[0.7rem]"
        :disabled="sessionsSaving"
        @click="signOutEverywhere"
      >
        {{ sessionsSaving ? "Revoking…" : "Sign out everywhere" }}
      </button>
      <p v-if="sessionsError" class="text-[0.7rem] font-semibold text-[var(--np-danger)]">{{ sessionsError }}</p>
    </div>
  </section>
</template>
