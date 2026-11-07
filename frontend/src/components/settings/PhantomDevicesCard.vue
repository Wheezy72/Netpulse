<script setup lang="ts">
/**
 * Inventory repair for proxy ARP, for Settings → System.
 *
 * A router that answers for addresses it does not own leaves a whole subnet of
 * device rows sharing its MAC — 255 "hosts" where there is one. Discovery no
 * longer writes those rows, but the ones already there stay until they are
 * removed. This shows exactly what would go first, and only deletes after a
 * second click: the preview is the point, not the button.
 */
import axios from "axios";
import { ref } from "vue";

interface PhantomKeep {
  id: number;
  ip_address: string;
  hostname: string | null;
  is_gateway: boolean;
}

interface PhantomClump {
  network_id: number | null;
  network_name: string | null;
  mac_address: string;
  rows: number;
  removable: number;
  keep: PhantomKeep;
  first_dropped: string | null;
  last_dropped: string | null;
}

interface PhantomReport {
  limit: number;
  inspected: number;
  removable: number;
  clumps: PhantomClump[];
}

interface PhantomPurge {
  deleted: number;
  clumps: PhantomClump[];
}

const report = ref<PhantomReport | null>(null);
const result = ref<string | null>(null);
const error = ref<string | null>(null);
const loading = ref(false);
const deleting = ref(false);
const armed = ref(false);

function describe(error_: unknown, fallback: string): string {
  const status = axios.isAxiosError(error_) ? error_.response?.status : undefined;
  if (status === 403) return "Only an admin can repair the inventory.";
  if (status === 401) return "Sign in again to repair the inventory.";
  if (status === 404) return "This backend does not have the maintenance routes yet.";
  return fallback;
}

async function check(): Promise<void> {
  loading.value = true;
  error.value = null;
  result.value = null;
  armed.value = false;
  try {
    const { data } = await axios.get<PhantomReport>("/api/maintenance/phantom-devices");
    report.value = data;
  } catch (error_: unknown) {
    report.value = null;
    error.value = describe(error_, "Could not read the inventory.");
  } finally {
    loading.value = false;
  }
}

async function prune(): Promise<void> {
  // First click arms, second click deletes: a delete this size is worth a
  // deliberate second press.
  if (!armed.value) {
    armed.value = true;
    return;
  }

  deleting.value = true;
  error.value = null;
  try {
    const { data } = await axios.post<PhantomPurge>("/api/maintenance/phantom-devices/prune");
    const networks = data.clumps.length;
    result.value =
      `Removed ${data.deleted} row(s) across ${networks} MAC(s), keeping each network's lowest address. ` +
      "Sweep again to rebuild the inventory.";
    report.value = null;
    armed.value = false;
  } catch (error_: unknown) {
    error.value = describe(error_, "The cleanup failed; nothing was removed.");
    armed.value = false;
  } finally {
    deleting.value = false;
  }
}
</script>

<template>
  <div class="space-y-3">
    <div class="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
      <div class="min-w-0">
        <p class="text-[0.8rem] font-semibold np-info-card-value">Phantom hosts</p>
        <p class="mt-0.5 text-[0.7rem] leading-relaxed np-info-card-text">
          A router answering for addresses it does not own leaves a whole subnet of rows carrying one
          MAC. Checking the inventory shows them; removing them keeps the router's own address.
        </p>
      </div>
      <button
        type="button"
        class="np-cyber-btn w-full shrink-0 rounded px-4 py-2 text-[0.75rem] sm:w-auto"
        :disabled="loading || deleting"
        @click="check"
      >
        {{ loading ? "Checking…" : "Check inventory" }}
      </button>
    </div>

    <p v-if="error" class="text-[0.7rem] font-semibold text-[var(--np-danger)]">{{ error }}</p>
    <p v-else-if="result" class="text-[0.7rem] font-semibold text-emerald-400">{{ result }}</p>

    <template v-else-if="report">
      <p v-if="report.clumps.length === 0" class="text-[0.7rem] leading-relaxed np-info-card-text">
        No MAC answers for more than {{ report.limit }} addresses across
        {{ report.inspected }} row(s). Nothing to clean up.
      </p>

      <template v-else>
        <div class="np-settings-section">
          <div
            v-for="clump in report.clumps"
            :key="`${clump.network_id ?? 'none'}-${clump.mac_address}`"
            class="flex flex-col gap-1 py-3 border-b border-[var(--np-border-subtle)] last:border-b-0 sm:flex-row sm:items-start sm:justify-between sm:gap-4"
          >
            <div class="min-w-0">
              <p class="text-[0.78rem] font-semibold np-info-card-value">
                {{ clump.network_name ?? "Network unknown" }}
              </p>
              <p class="mt-0.5 font-mono text-[0.68rem] np-info-card-text">{{ clump.mac_address }}</p>
              <p class="mt-0.5 text-[0.68rem] leading-relaxed np-info-card-text">
                keeps {{ clump.keep.ip_address }}<span v-if="clump.keep.hostname"> “{{ clump.keep.hostname }}”</span><span v-if="clump.keep.is_gateway"> (gateway)</span>
              </p>
            </div>
            <div class="shrink-0 sm:text-right">
              <span class="block font-mono text-[0.7rem] font-bold text-amber-400">
                {{ clump.removable }} rows
              </span>
              <span class="block text-[0.65rem] np-info-card-text">
                {{ clump.first_dropped }} … {{ clump.last_dropped }}
              </span>
            </div>
          </div>
        </div>

        <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <p class="text-[0.7rem] leading-relaxed np-info-card-text">
            {{ report.removable }} of {{ report.inspected }} rows have no host behind them.
            <span v-if="armed" class="font-semibold text-[var(--np-danger)]">
              This cannot be undone.
            </span>
          </p>
          <div class="flex shrink-0 items-center gap-2 sm:justify-end">
            <button
              v-if="armed"
              type="button"
              class="rounded border border-[var(--np-border-subtle)] px-2.5 py-1 text-[0.7rem] font-semibold text-[var(--np-text-muted)] transition-colors hover:border-[var(--np-text-muted)]"
              :disabled="deleting"
              @click="armed = false"
            >
              Cancel
            </button>
            <button
              type="button"
              class="rounded border border-[var(--np-danger)] px-2.5 py-1 text-[0.7rem] font-bold text-[var(--np-danger)] transition-colors hover:bg-[var(--np-danger)]/10 disabled:opacity-50"
              :disabled="deleting"
              @click="prune"
            >
              {{ deleting ? "Removing…" : armed ? `Delete ${report.removable} rows` : `Remove ${report.removable} rows` }}
            </button>
          </div>
        </div>
      </template>
    </template>
  </div>
</template>
