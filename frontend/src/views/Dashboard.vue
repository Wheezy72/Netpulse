<script setup lang="ts">
/**
 * Dashboard.vue
 *
 * This is the "Single Pane of Glass" layout. It exposes:
 *  - Pulse: real-time telemetry (latency, jitter, Internet Health).
 *  - Eye: topology & reconnaissance.
 *  - Brain: automation and scripting.
 *  - Vault: historical data and PCAP exports.
 *
 * It is intentionally structured with clear regions so you can swap,
 * resize, or add panels without refactoring the entire layout.
 */

import axios from "axios";
import { computed, ref } from "vue";

type ReconTargetService = {
  port: number;
  protocol: string;
  service: string;
};

type NmapRecommendation = {
  reason: string;
  scripts: string[];
};

const selectedTarget = ref("");
const selectedServices = ref<ReconTargetService[]>([]);
const recommendations = ref<NmapRecommendation[]>([]);
const isScanning = ref(false);
const scanError = ref<string | null>(null);

/**
 * Trigger an on-demand Nmap scan for the selected target.
 * The backend returns detected services and recommended Nmap scripts.
 */
async function scanTarget(): Promise<void> {
  scanError.value = null;

  const target = selectedTarget.value.trim();
  if (!target) {
    scanError.value = "Please enter a target hostname or IP address.";
    return;
  }

  isScanning.value = true;
  try {
    const { data } = await axios.post("/api/recon/scan", { target });
    selectedServices.value = data.services ?? [];
    recommendations.value = data.recommendations ?? [];
  } catch (error: unknown) {
    scanError.value = "Scan failed. Ensure the backend can reach the target and Nmap is installed.";
    selectedServices.value = [];
    recommendations.value = [];
  } finally {
    isScanning.value = false;
  }
}

const hasRecommendations = computed(() => recommendations.value.length > 0);
</script>

<template>
  <div class="grid gap-4 xl:grid-cols-3 xl:grid-rows-6">
    <!-- Pulse: Real-Time Telemetry -->
    <section
      class="np-panel relative col-span-3 grid gap-4 p-4 xl:col-span-2 xl:row-span-2 np-scanlines overflow-hidden"
    >
      <header class="np-panel-header">
        <div class="flex items-center gap-2">
          <span class="np-panel-title np-text-glow">Pulse: Internet Health</span>
          <span class="text-[0.6rem] uppercase tracking-[0.18em] text-[var(--np-muted-text)]">
            Latency · Jitter · Packet Loss
          </span>
        </div>
        <div class="flex items-center gap-3 text-xs text-[var(--np-muted-text)]">
          <span>Gateway / ISP / Cloudflare</span>
          <span class="h-1 w-10 rounded-full bg-emerald-400/60"></span>
        </div>
      </header>

      <div class="grid gap-4 md:grid-cols-4">
        <div class="md:col-span-3">
          <div
            id="pulse-chart"
            class="relative h-48 w-full rounded-md border border-cyan-400/30 bg-black/40"
          >
            <div
              class="absolute inset-0 flex items-center justify-center text-xs text-cyan-200/70"
            >
              Telemetry chart placeholder (Apache ECharts)
            </div>
          </div>
        </div>

        <div class="flex flex-col gap-3 text-xs">
          <div class="rounded-md border border-emerald-400/40 bg-black/50 p-3">
            <div class="flex items-baseline justify-between">
              <span class="text-[0.6rem] uppercase tracking-[0.18em] text-emerald-300">
                Internet Health
              </span>
              <span class="text-lg font-semibold text-emerald-300">92%</span>
            </div>
            <p class="mt-1 text-[0.7rem] text-cyan-100/80">
              Based on current latency, jitter and packet loss across your WAN.
            </p>
          </div>

          <div class="space-y-2">
            <div class="flex items-center justify-between">
              <span>Gateway</span>
              <span class="text-cyan-200">4 ms</span>
            </div>
            <div class="flex items-center justify-between">
              <span>ISP Edge</span>
              <span class="text-cyan-200">18 ms</span>
            </div>
            <div class="flex items-center justify-between">
              <span>Cloudflare</span>
              <span class="text-cyan-200">22 ms</span>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- Eye: Topology & Recon -->
    <section
      class="np-panel relative col-span-3 grid gap-4 p-4 xl:col-span-1 xl:row-span-3"
    >
      <header class="np-panel-header">
        <div class="flex flex-col">
          <span class="np-panel-title">Eye: Topology &amp; Recon</span>
          <span class="text-[0.7rem] text-[var(--np-muted-text)]">
            Passive discovery + Nmap insights.
          </span>
        </div>
        <span class="text-[0.65rem] uppercase tracking-[0.16em] text-[var(--np-muted-text)]">
          Cytoscape.js Graph
        </span>
      </header>

      <div class="grid gap-3 lg:grid-rows-[minmax(0,2fr)_minmax(0,1.4fr)]">
        <div
          id="topology-graph"
          class="relative h-52 w-full rounded-md border border-cyan-400/30 bg-black/40"
        >
          <div
            class="absolute inset-0 flex items-center justify-center text-xs text-cyan-200/70"
          >
            Topology placeholder (Cytoscape.js)
          </div>
        </div>

        <!-- Nmap script advisor / recon playbook -->
        <div class="rounded-md border border-cyan-400/30 bg-black/40 p-3 text-xs">
          <div class="flex items-center justify-between">
            <div>
              <h3 class="text-[0.7rem] uppercase tracking-[0.16em] text-cyan-200">
                Recon Playbook
              </h3>
              <p class="mt-0.5 text-[0.7rem] text-cyan-100/80">
                Select a target and get context-aware Nmap script recommendations.
              </p>
            </div>
            <span class="rounded-full border border-cyan-400/40 px-2 py-0.5 text-[0.6rem]">
              Eye · Advisor
            </span>
          </div>

          <div class="mt-2 flex flex-col gap-2">
            <label class="text-[0.7rem] text-[var(--np-muted-text)]">
              Target (IP / Hostname)
              <input
                v-model="selectedTarget"
                type="text"
                class="mt-1 w-full rounded-md border bg-black/60 px-2 py-1 text-[0.75rem]
                       focus:outline-none focus:ring-1 focus:ring-cyan-400"
                placeholder="10.0.0.15"
              />
            </label>

            <div class="flex items-center gap-2 text-[0.7rem]">
              <button
                type="button"
                @click="scanTarget"
                class="inline-flex items-center justify-center rounded-md border
                       border-cyan-400/60 bg-black/80 px-2.5 py-1 text-[0.7rem] font-medium
                       text-cyan-200 hover:bg-cyan-500/10 disabled:opacity-50"
                :disabled="isScanning"
              >
                <span v-if="!isScanning">Scan with Nmap</span>
                <span v-else>Scanning…</span>
              </button>
              <span v-if="scanError" class="text-rose-300">
                {{ scanError }}
              </span>
            </div>

            <div v-if="selectedServices.length" class="mt-2 grid gap-2 md:grid-cols-2">
              <div v-for="svc in selectedServices" :key="`${svc.protocol}-${svc.port}`" class="text-[0.7rem]">
                <div class="flex items-center justify-between">
                  <span class="font-mono text-cyan-200">
                    {{ svc.protocol }}/{{ svc.port }}
                  </span>
                  <span class="rounded bg-cyan-500/10 px-1.5 py-0.5 text-[0.65rem]">
                    {{ svc.service }}
                  </span>
                </div>
              </div>
            </div>

            <div class="mt-2 border-t border-cyan-400/20 pt-2">
              <div v-if="hasRecommendations" class="space-y-2">
                <div
                  v-for="(rec, idx) in recommendations"
                  :key="idx"
                  class="rounded-md border border-cyan-400/30 bg-black/60 p-2"
                >
                  <p class="text-[0.7rem] font-semibold text-cyan-200">
                    {{ rec.reason }}
                  </p>
                  <p class="mt-1 text-[0.7rem] text-cyan-100/80">
                    Suggested Nmap scripts:
                  </p>
                  <div class="mt-1 flex flex-wrap gap-1">
                    <span
                      v-for="script in rec.scripts"
                      :key="script"
                      class="rounded border border-cyan-400/40 bg-black/70 px-1.5 py-0.5 text-[0.65rem] font-mono"
                    >
                      {{ script }}
                    </span>
                  </div>
                </div>
              </div>
              <p v-else class="text-[0.7rem] text-cyan-100/80">
                Enter a target and run a scan to see tailored Nmap script suggestions.
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- Brain: Automation & Script Hub -->
    <section class="np-panel col-span-3 xl:col-span-2 xl:row-span-2 p-4">
      <header class="np-panel-header">
        <div class="flex flex-col">
          <span class="np-panel-title">Brain: Automation Hub</span>
          <span class="text-[0.7rem] text-[var(--np-muted-text)]">
            Upload Python scripts, orchestrate offensive/defensive playbooks.
          </span>
        </div>
        <span class="text-[0.65rem] uppercase tracking-[0.16em] text-[var(--np-muted-text)]">
          XTerm.js Console
        </span>
      </header>

      <div class="grid gap-4 md:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
        <div
          id="brain-terminal"
          class="relative h-56 rounded-md border border-cyan-400/30 bg-black/90 np-scanlines"
        >
          <div
            class="absolute inset-0 flex items-center justify-center text-xs text-cyan-200/70"
          >
            XTerm.js terminal placeholder (script output, interactive shell)
          </div>
        </div>

        <div class="flex flex-col gap-3 text-xs">
          <div class="rounded-md border border-cyan-400/30 bg-black/50 p-3">
            <h3 class="text-[0.7rem] uppercase tracking-[0.16em] text-cyan-200">
              Script Hub
            </h3>
            <p class="mt-1 text-[0.7rem] text-cyan-100/80">
              Drag &amp; drop Python files to run them as Smart Scripts. NetPulse will capture
              logs, results, and surface them here.
            </p>
          </div>

          <ul class="space-y-1 text-[0.7rem]">
            <li class="flex items-center justify-between">
              <span class="font-mono text-cyan-200">backup_switch.py</span>
              <span class="rounded bg-emerald-500/20 px-2 py-0.5 text-emerald-300">
                Prebuilt · Config Backup
              </span>
            </li>
            <li class="flex items-center justify-between">
              <span class="font-mono text-cyan-200">kill_switch.py</span>
              <span class="rounded bg-rose-500/20 px-2 py-0.5 text-rose-300">
                Prebuilt · Connection Reset
              </span>
            </li>
            <li class="flex items-center justify-between">
              <span class="font-mono text-cyan-200">custom_probe.py</span>
              <span class="rounded bg-sky-500/20 px-2 py-0.5 text-sky-300">
                Your custom Smart Script
              </span>
            </li>
          </ul>
        </div>
      </div>
    </section>

    <!-- Vault: Time Machine & PCAP Export -->
    <section class="np-panel col-span-3 xl:col-span-1 xl:row-span-2 p-4">
      <header class="np-panel-header">
        <div class="flex flex-col">
          <span class="np-panel-title">Vault: Time Machine</span>
          <span class="text-[0.7rem] text-[var(--np-muted-text)]">
            Scroll back in time, export PCAP slices.
          </span>
        </div>
      </header>

      <div class="flex h-full flex-col gap-3 text-xs">
        <div class="rounded-md border border-cyan-400/30 bg-black/50 p-3">
          <label class="flex flex-col gap-1 text-[0.7rem]">
            Time Window
            <input
              type="datetime-local"
              class="rounded-md border border-cyan-400/30 bg-black/70 px-2 py-1 text-[0.75rem]
                     focus:outline-none focus:ring-1 focus:ring-cyan-400"
            />
          </label>
          <p class="mt-1 text-[0.7rem] text-cyan-100/80">
            Choose a point in time (e.g. yesterday 3:00 PM) to replay metrics in the Pulse
            panel.
          </p>
        </div>

        <button
          type="button"
          class="mt-auto inline-flex items-center justify-center rounded-md border
                 border-cyan-400/40 bg-black/70 px-3 py-2 text-[0.75rem] font-medium
                 text-cyan-200 hover:bg-cyan-500/10"
        >
          Export Last 5 Minutes as PCAP
        </button>
      </div>
    </section>
  </div>
</template>