<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";

import ToggleSwitch from "../components/ui/ToggleSwitch.vue";

type Theme = "nightshade" | "sysadmin";

interface Props {
  theme: Theme;
}

defineProps<Props>();

const splunkEndpoint = ref("");
const splunkToken = ref("");
const splunkIndex = ref("main");
const forwardDiscoveryAnomalies = ref(true);
const enableAutomatedSwitchShutdown = ref(false);
const triggerImmediateDeepAudits = ref(false);
const heartbeatActive = ref(true);

const telemetryFeed = ref([
  {
    signature: "arp:00:25:96:ff:12:9a",
    host: "10.40.12.18",
    mac: "00:25:96:ff:12:9a",
    segment: "vlan-40",
    state: "trusted",
    accent: "emerald",
  },
  {
    signature: "dhcp.discover:3c:52:82:1d:7a:11",
    host: "10.40.12.44",
    mac: "3c:52:82:1d:7a:11",
    segment: "vlan-40",
    state: "new signature",
    accent: "blue",
  },
  {
    signature: "arp:8c:85:90:1f:aa:ef",
    host: "10.40.12.77",
    mac: "8c:85:90:1f:aa:ef",
    segment: "containment",
    state: "isolated",
    accent: "red",
  },
]);

let heartbeatTimer: number | undefined;

const heartbeatLabel = computed(() => (splunkEndpoint.value && splunkToken.value ? "live" : "standby"));

function accentClass(accent: string): string {
  if (accent === "red") return "text-red-400 bg-red-500/10";
  if (accent === "blue") return "text-fuchsia-400 bg-fuchsia-500/10";
  return "text-emerald-400 bg-emerald-500/10";
}

onMounted(() => {
  heartbeatTimer = window.setInterval(() => {
    heartbeatActive.value = !heartbeatActive.value;
  }, 1000);
});

onBeforeUnmount(() => {
  if (heartbeatTimer) window.clearInterval(heartbeatTimer);
});
</script>

<template>
  <div class="min-h-full space-y-4" style="background: var(--np-bg); color: var(--np-text);">
    <header class="flex items-end justify-between px-1">
      <div>
        <p class="text-[0.65rem] uppercase tracking-[0.45em] text-white/30">incident response console</p>
        <h1 class="mt-2 text-2xl font-semibold tracking-tight text-white">automation</h1>
      </div>
      <div class="flex items-center gap-2 rounded-full border border-white/[0.04] bg-[#0B0F17]/80 px-3 py-1.5 backdrop-blur-md">
        <span
          class="h-2.5 w-2.5 rounded-full"
          :class="heartbeatActive ? 'bg-fuchsia-400 shadow-[0_0_16px_rgba(217,70,239,0.55)]' : 'bg-white/20'"
        />
        <span class="np-mono text-[11px] uppercase tracking-[0.35em] text-white/45">{{ heartbeatLabel }}</span>
      </div>
    </header>

    <div class="grid gap-4 lg:grid-cols-[1.65fr_0.95fr]">
      <section class="rounded-3xl border border-white/[0.04] bg-[#0B0F17]/80 backdrop-blur-md shadow-2xl shadow-black/40">
        <div class="flex items-center justify-between border-b border-white/[0.04] px-5 py-4">
          <div>
            <p class="text-[0.65rem] uppercase tracking-[0.4em] text-white/30">stream</p>
            <h2 class="mt-1 text-lg font-semibold text-white">Subnet Traffic Stream</h2>
          </div>
          <div class="rounded-full border border-white/[0.04] bg-white/[0.03] px-3 py-1">
            <span class="np-mono text-[11px] uppercase tracking-[0.32em] text-emerald-400">live feed</span>
          </div>
        </div>

        <div class="max-h-[72vh] overflow-y-auto">
          <article
            v-for="entry in telemetryFeed"
            :key="entry.signature"
            class="flex flex-col gap-3 px-5 py-4 transition-colors hover:bg-white/[0.02]"
          >
            <div class="flex items-start justify-between gap-4">
              <div class="min-w-0">
                <div class="flex flex-wrap items-center gap-2">
                  <span
                    class="rounded-full px-2 py-1 font-mono text-[10px] uppercase tracking-[0.28em]"
                    :class="accentClass(entry.accent)"
                  >
                    {{ entry.state }}
                  </span>
                  <span class="np-mono text-[12px] text-white/90">{{ entry.host }}</span>
                </div>
                <p class="np-mono mt-2 text-[12px] text-white/55">{{ entry.signature }}</p>
              </div>
              <div class="text-right np-mono text-[11px] text-white/45">
                <div>{{ entry.mac }}</div>
                <div class="mt-1 uppercase tracking-[0.3em]">{{ entry.segment }}</div>
              </div>
            </div>
          </article>
        </div>
      </section>

      <aside class="rounded-3xl border border-white/[0.04] bg-[#0B0F17]/80 backdrop-blur-md shadow-2xl shadow-black/40">
        <div class="border-b border-white/[0.04] px-5 py-4">
          <p class="text-[0.65rem] uppercase tracking-[0.4em] text-white/30">orchestration</p>
          <h2 class="mt-1 text-lg font-semibold text-white">Orchestration Matrix</h2>
        </div>

        <div class="space-y-5 px-5 py-4">
          <section class="space-y-3">
            <div>
              <label class="block text-[11px] lowercase tracking-[0.28em] text-white/45">splunk hec endpoint</label>
              <input
                v-model="splunkEndpoint"
                type="text"
                placeholder="https://splunk.example.com:8088/services/collector"
              class="mt-2 w-full rounded-2xl border border-white/[0.04] bg-black/40 px-4 py-3 np-mono text-[12px] text-white outline-none placeholder:text-white/20 focus:border-fuchsia-400/40"
              />
            </div>

            <div class="grid gap-3 sm:grid-cols-2">
              <div>
                <label class="block text-[11px] lowercase tracking-[0.28em] text-white/45">hec token</label>
                <input
                  v-model="splunkToken"
                  type="password"
                  placeholder="••••••••••••••••"
                  class="mt-2 w-full rounded-2xl border border-white/[0.04] bg-black/40 px-4 py-3 np-mono text-[12px] text-white outline-none placeholder:text-white/20 focus:border-fuchsia-400/40"
                />
              </div>
              <div>
                <label class="block text-[11px] lowercase tracking-[0.28em] text-white/45">index</label>
                <input
                  v-model="splunkIndex"
                  type="text"
                  class="mt-2 w-full rounded-2xl border border-white/[0.04] bg-black/40 px-4 py-3 np-mono text-[12px] text-white outline-none focus:border-fuchsia-400/40"
                />
              </div>
            </div>

            <div class="flex items-center justify-between rounded-2xl border border-white/[0.04] bg-white/[0.03] px-4 py-3">
              <div>
                <p class="text-[11px] lowercase tracking-[0.28em] text-white/45">heartbeat</p>
                <p class="np-mono mt-1 text-[12px] text-white/70">{{ heartbeatLabel }}</p>
              </div>
              <div
                class="h-2.5 w-2.5 rounded-full"
                :class="heartbeatActive ? 'bg-fuchsia-400 shadow-[0_0_18px_rgba(217,70,239,0.65)]' : 'bg-white/15'"
              />
            </div>
          </section>

          <section class="space-y-4">
            <div class="flex items-center justify-between gap-4 rounded-2xl border border-white/[0.04] bg-white/[0.02] px-4 py-3">
              <div>
                <p class="text-[11px] lowercase tracking-[0.28em] text-white/45">forward discovery anomalies to splunk</p>
                <p class="mt-1 text-[12px] text-white/50">stream unverified signatures as JSON.</p>
              </div>
              <ToggleSwitch v-model="forwardDiscoveryAnomalies" :theme="theme" />
            </div>

            <div class="flex items-center justify-between gap-4 rounded-2xl border border-white/[0.04] bg-white/[0.02] px-4 py-3">
              <div>
                <p class="text-[11px] lowercase tracking-[0.28em] text-white/45">enable automated switch port shutdown</p>
                <p class="mt-1 text-[12px] text-white/50">admin-only containment on compromised ports.</p>
              </div>
              <ToggleSwitch v-model="enableAutomatedSwitchShutdown" :theme="theme" />
            </div>

            <div class="flex items-center justify-between gap-4 rounded-2xl border border-white/[0.04] bg-white/[0.02] px-4 py-3">
              <div>
                <p class="text-[11px] lowercase tracking-[0.28em] text-white/45">trigger immediate deep audits</p>
                <p class="mt-1 text-[12px] text-white/50">launch extended sweeps and baseline checks.</p>
              </div>
              <ToggleSwitch v-model="triggerImmediateDeepAudits" :theme="theme" />
            </div>
          </section>
        </div>
      </aside>
    </div>
  </div>
</template>
