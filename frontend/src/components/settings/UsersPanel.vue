<script setup lang="ts">
/**
 * Admin-only account roster.
 *
 * Sign-up is closed on this instance by design: the only way a second person
 * gets in is an admin creating them here. Before this panel existed the API
 * enforced that rule while the UI offered nothing but the public Register page,
 * whose requests were (correctly) refused — the account simply could not be
 * added.
 *
 * Roles stay at two: admin (everything) and viewer (read-only).
 */
import axios from "axios";
import { computed, onMounted, ref } from "vue";

import { useAuthStore } from "../../stores/auth";
import { describeRequestError } from "../../utils/requestError";

const auth = useAuthStore();

interface Account {
  id: number;
  username: string;
  email: string | null;
  full_name: string | null;
  role: string;
  created_at: string | null;
}

const accounts = ref<Account[]>([]);
const loading = ref(true);
const loadError = ref<string | null>(null);

const username = ref("");
const email = ref("");
const password = ref("");
const role = ref<"viewer" | "admin">("viewer");
const saving = ref(false);
const message = ref<string | null>(null);
// Roster feedback belongs next to the roster, not under the "Add account"
// button, which is where a role change used to report itself.
const rosterMessage = ref<string | null>(null);
const error = ref<string | null>(null);

const canSubmit = computed(
  () => username.value.trim().length >= 3 && password.value.length >= 8 && !saving.value,
);

// Delete is a two-step action per row: the first click arms it, the second
// removes the account. A browser confirm() would break the layout rhythm and
// cannot say "this is the only admin", which is the case that actually matters.
const pendingDeleteId = ref<number | null>(null);
const deletingId = ref<number | null>(null);
const roleSavingId = ref<number | null>(null);
const rowError = ref<{ id: number; message: string } | null>(null);

function isSelf(account: Account): boolean {
  return auth.user?.id === account.id;
}

async function deleteAccount(account: Account): Promise<void> {
  if (pendingDeleteId.value !== account.id) {
    pendingDeleteId.value = account.id;
    rowError.value = null;
    return;
  }

  deletingId.value = account.id;
  rowError.value = null;
  try {
    await axios.delete(`/api/auth/users/${account.id}`);
    accounts.value = accounts.value.filter((entry) => entry.id !== account.id);
    pendingDeleteId.value = null;
    rosterMessage.value = `${account.username} was removed.`;
  } catch (err) {
    rowError.value = {
      id: account.id,
      message: describeRequestError(err, "Could not delete that account."),
    };
    pendingDeleteId.value = null;
  } finally {
    deletingId.value = null;
  }
}

function onRoleChange(account: Account, event: Event): void {
  const select = event.target as HTMLSelectElement;
  const nextRole = select.value as "viewer" | "admin";
  void changeRole(account, nextRole, select);
}

async function changeRole(
  account: Account,
  nextRole: "viewer" | "admin",
  select: HTMLSelectElement,
): Promise<void> {
  if (account.role === nextRole) return;

  roleSavingId.value = account.id;
  rowError.value = null;
  rosterMessage.value = null;
  try {
    const { data } = await axios.patch<Account>(`/api/auth/users/${account.id}`, {
      role: nextRole,
    });
    const index = accounts.value.findIndex((entry) => entry.id === account.id);
    if (index !== -1) accounts.value[index] = data;
    rosterMessage.value = `${account.username} is now ${data.role}. The new role applies on their next request.`;
  } catch (err) {
    // The native select already shows the attempted value; put it back so the
    // row cannot advertise a role the server refused.
    select.value = account.role;
    rowError.value = {
      id: account.id,
      message: describeRequestError(err, "Could not change that role."),
    };
  } finally {
    roleSavingId.value = null;
  }
}

async function loadAccounts(): Promise<void> {
  loading.value = true;
  loadError.value = null;
  try {
    const { data } = await axios.get<Account[]>("/api/auth/users");
    accounts.value = data;
  } catch (err) {
    loadError.value = describeRequestError(err, "Could not load the account list.");
    accounts.value = [];
  } finally {
    loading.value = false;
  }
}

async function createAccount(): Promise<void> {
  error.value = null;
  message.value = null;

  const candidate = username.value.trim();
  if (candidate.length < 3) {
    error.value = "Usernames need at least 3 characters.";
    return;
  }
  if (password.value.length < 8) {
    error.value = "Use at least 8 characters for the initial password.";
    return;
  }

  saving.value = true;
  try {
    await axios.post("/api/auth/users", {
      username: candidate,
      email: email.value.trim() || null,
      password: password.value,
      role: role.value,
    });
    message.value = `${candidate} can now sign in as ${role.value}.`;
    username.value = "";
    email.value = "";
    password.value = "";
    role.value = "viewer";
    await loadAccounts();
  } catch (err) {
    error.value = describeRequestError(err, "Could not create that account.");
  } finally {
    saving.value = false;
  }
}

function formatCreated(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleDateString();
}

onMounted(loadAccounts);
</script>

<template>
  <section class="np-panel p-4 space-y-6">
    <header class="np-panel-header -mx-4 -mt-4 mb-4 px-4">
      <div class="flex flex-col">
        <span class="np-panel-title">Users</span>
        <span class="text-[0.7rem] text-[var(--np-text-dim)]">
          Accounts with access to this console.
        </span>
      </div>
    </header>

    <!-- Create ------------------------------------------------------------>
    <div class="np-settings-section space-y-3">
      <div>
        <p class="np-settings-section-title">Add an account</p>
        <p class="text-[0.7rem] text-[var(--np-text-dim)]">
          Give the person the initial password separately. They are asked to
          choose their own the first time they sign in.
        </p>
      </div>

      <div class="grid gap-3 md:grid-cols-2">
        <div class="flex flex-col gap-1">
          <label for="new-user-name" class="text-[0.7rem] font-semibold text-[var(--np-text-muted)]">
            Username
          </label>
          <input
            id="new-user-name"
            v-model="username"
            type="text"
            name="username"
            autocomplete="off"
            spellcheck="false"
            class="np-neon-input rounded px-3 py-2"
            placeholder="jdoe"
          />
        </div>

        <div class="flex flex-col gap-1">
          <label for="new-user-email" class="text-[0.7rem] font-semibold text-[var(--np-text-muted)]">
            Email <span class="font-normal text-[var(--np-text-dim)]">(optional)</span>
          </label>
          <input
            id="new-user-email"
            v-model="email"
            type="email"
            name="email"
            autocomplete="off"
            spellcheck="false"
            class="np-neon-input rounded px-3 py-2"
            placeholder="jdoe@example.com"
          />
        </div>

        <div class="flex flex-col gap-1">
          <label for="new-user-password" class="text-[0.7rem] font-semibold text-[var(--np-text-muted)]">
            Initial password
          </label>
          <input
            id="new-user-password"
            v-model="password"
            type="password"
            name="new-password"
            autocomplete="new-password"
            class="np-neon-input rounded px-3 py-2"
            placeholder="At least 8 characters"
          />
        </div>

        <div class="flex flex-col gap-1">
          <label for="new-user-role" class="text-[0.7rem] font-semibold text-[var(--np-text-muted)]">
            Role
          </label>
          <select id="new-user-role" v-model="role" class="np-neon-input cursor-pointer rounded px-3 py-2">
            <option value="viewer">Viewer — read-only</option>
            <option value="admin">Admin — full control</option>
          </select>
          <p class="text-[0.65rem] text-[var(--np-text-dim)]">
            Viewers can see everything but change nothing: no scans, scripts,
            backups or console sessions.
          </p>
        </div>
      </div>

      <div class="flex flex-wrap items-center gap-3">
        <button
          type="button"
          class="np-cyber-btn np-cyber-btn--solid rounded px-4 py-2 text-[0.7rem]"
          :disabled="!canSubmit"
          @click="createAccount"
        >
          {{ saving ? "Adding…" : "Add account" }}
        </button>
        <p v-if="error" class="text-[0.7rem] font-semibold text-[var(--np-danger)]">{{ error }}</p>
        <p v-else-if="message" class="text-[0.7rem] font-semibold text-[var(--np-success)]">{{ message }}</p>
      </div>
    </div>

    <!-- Roster ------------------------------------------------------------>
    <div class="np-settings-section">
      <p class="np-settings-section-title">Existing accounts</p>
      <p class="mb-2 text-[0.68rem] text-[var(--np-text-dim)]">
        Role changes apply immediately. The last remaining admin cannot be
        demoted.
      </p>
      <p
        v-if="rosterMessage"
        class="mb-2 text-[0.7rem] font-semibold text-[var(--np-success)]"
        role="status"
      >
        {{ rosterMessage }}
      </p>

      <p v-if="loading" class="text-[0.75rem] text-[var(--np-text-dim)]">Loading accounts…</p>
      <div v-else-if="loadError" class="flex flex-wrap items-center gap-2">
        <p class="text-[0.75rem] font-semibold text-[var(--np-danger)]">{{ loadError }}</p>
        <button
          type="button"
          class="rounded border border-[var(--np-border-subtle)] px-2.5 py-1 text-[0.65rem] font-semibold text-[var(--np-text)] transition-colors hover:bg-[var(--np-surface-hover)]"
          @click="loadAccounts"
        >
          Retry
        </button>
      </div>
      <p v-else-if="accounts.length === 0" class="text-[0.75rem] text-[var(--np-text-dim)]">
        No accounts yet.
      </p>
      <ul v-else class="divide-y divide-[var(--np-border-subtle)]">
        <li
          v-for="account in accounts"
          :key="account.id"
          class="flex flex-wrap items-center justify-between gap-3 py-2.5 min-w-0"
        >
          <div class="min-w-0">
            <p class="truncate text-[0.8rem] font-semibold text-[var(--np-text)]">
              {{ account.username }}
              <span v-if="isSelf(account)" class="ml-1 text-[0.6rem] font-bold uppercase tracking-wider text-[var(--np-accent)]">
                you
              </span>
              <span v-if="account.full_name" class="font-normal text-[var(--np-text-dim)]">
                · {{ account.full_name }}
              </span>
            </p>
            <p class="truncate text-[0.68rem] text-[var(--np-text-dim)]">
              <template v-if="account.email">{{ account.email }}</template>
              <template v-else>No email on file</template>
              · added {{ formatCreated(account.created_at) }}
            </p>
            <p v-if="rowError?.id === account.id" class="mt-1 text-[0.68rem] font-semibold text-[var(--np-danger)]">
              {{ rowError.message }}
            </p>
          </div>

          <div class="flex shrink-0 items-center gap-2">
            <!-- Your own role is read-only: a mis-click here would instantly
                 remove the permissions of the person clicking. -->
            <select
              v-if="!isSelf(account)"
              class="np-neon-input cursor-pointer rounded px-2 py-1 text-[0.62rem] font-semibold uppercase tracking-wider"
              :class="
                account.role === 'admin'
                  ? 'text-[var(--np-accent)]'
                  : 'text-[var(--np-text-muted)]'
              "
              :value="account.role"
              :disabled="roleSavingId === account.id || deletingId === account.id"
              :aria-label="`Role for ${account.username}`"
              @change="onRoleChange(account, $event)"
            >
              <option value="viewer">Viewer</option>
              <option value="admin">Admin</option>
            </select>
            <span
              v-else
              class="rounded-full border px-2 py-0.5 text-[0.6rem] font-bold uppercase tracking-wider"
              :class="
                account.role === 'admin'
                  ? 'border-[var(--np-accent-border)] text-[var(--np-accent)]'
                  : 'border-[var(--np-border-subtle)] text-[var(--np-text-dim)]'
              "
            >
              {{ account.role }}
            </span>

            <!-- Your own row offers no delete: the API refuses it anyway, so
                 the button would only ever produce an error. -->
            <span
              v-if="isSelf(account)"
              class="text-[0.62rem] font-semibold text-[var(--np-text-dim)]"
              title="Ask another admin to change your role"
            >
              signed in
            </span>
            <span
              v-else-if="roleSavingId === account.id"
              class="text-[0.62rem] font-semibold text-[var(--np-text-dim)]"
            >
              Changing…
            </span>
            <template v-else>
              <button
                v-if="pendingDeleteId !== account.id"
                type="button"
                class="rounded border border-[var(--np-border-subtle)] px-2.5 py-1 text-[0.65rem] font-semibold text-[var(--np-text-muted)] transition-colors hover:border-[var(--np-danger)] hover:text-[var(--np-danger)]"
                :disabled="deletingId === account.id"
                @click="deleteAccount(account)"
              >
                Delete
              </button>
              <template v-else>
                <button
                  type="button"
                  class="rounded border border-[var(--np-danger)] px-2.5 py-1 text-[0.65rem] font-bold text-[var(--np-danger)] transition-colors hover:bg-[var(--np-danger)]/10"
                  :disabled="deletingId === account.id"
                  @click="deleteAccount(account)"
                >
                  {{ deletingId === account.id ? "Removing…" : "Confirm" }}
                </button>
                <button
                  type="button"
                  class="rounded px-2 py-1 text-[0.65rem] font-semibold text-[var(--np-text-dim)] transition-colors hover:text-[var(--np-text)]"
                  @click="pendingDeleteId = null"
                >
                  Cancel
                </button>
              </template>
            </template>
          </div>
        </li>
      </ul>
    </div>
  </section>
</template>
