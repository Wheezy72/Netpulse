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

import { useAuthStore } from "../../stores/auth";
import { describeRequestError } from "../../utils/requestError";

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
  if (newPassword.value.length < 6) {
    passwordError.value = "New password must be at least 6 characters.";
    return;
  }
  if (newPassword.value !== confirmPassword.value) {
    passwordError.value = "The two new passwords do not match.";
    return;
  }

  passwordSaving.value = true;
  try {
    await axios.post("/api/auth/change-password", {
      current_password: currentPassword.value,
      new_password: newPassword.value,
    });
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

onMounted(async () => {
  if (!auth.user) await auth.loadUser();
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
        <p id="account-email-help" class="text-[0.65rem] text-[var(--np-text-dim)]">
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
          Use at least 6 characters. You stay signed in on this device after the change.
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
        <p id="account-password-help" class="text-[0.65rem] text-[var(--np-text-dim)]">
          Changing the password does not sign out other sessions.
        </p>
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
  </section>
</template>
