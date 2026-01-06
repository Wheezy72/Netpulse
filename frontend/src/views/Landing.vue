<script setup lang="ts">
import Login from "./Login.vue";

type Theme = "cyberdeck" | "sysadmin";

interface Props {
  theme: Theme;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  (e: "login-success", token: string): void;
}>();
</script>

<template>
  <div
    class="min-h-[calc(100vh-4rem)] flex items-stretch justify-center"
    :class="theme === 'cyberdeck' ? 'np-landing-cd' : ''"
  >
    <!-- CyberDeck landing -->
    <section
      v-if="theme === 'cyberdeck'"
      class="mx-auto grid w-full max-w-6xl gap-8 lg:grid-cols-[minmax(0,1.7fr)_minmax(0,1fr)]"
    >
      <div
        class="relative overflow-hidden rounded-xl border border-cyan-400/40 bg-black/60 p-6 np-scanlines"
      >
        <div class="absolute inset-0 pointer-events-none">
          <div
            class="absolute -top-24 -left-24 h-64 w-64 rounded-full bg-cyan-500/10 blur-3xl"
          ></div>
          <div
            class="absolute -bottom-24 -right-24 h-64 w-64 rounded-full bg-purple-500/10 blur-3xl"
          ></div>
        </div>
        <div class="relative flex h-full flex-col justify-between gap-6">
          <header>
            <p class="text-[0.7rem] uppercase tracking-[0.3em] text-cyan-300">
              Network Console · CyberDeck Mode
            </p>
            <h2
              class="mt-3 text-3xl font-semibold tracking-wide text-cyan-100 np-text-glow"
            >
              See your entire network in a cool ops console.
            </h2>
            <p class="mt-3 text-sm text-cyan-100/80">
              NetPulse Enterprise is your home-lab NOC and SOC in one view.
              Monitor Internet Health, map devices, run Smart Scripts, capture
              PCAPs, and explore your network in a focused, operator-style console -
              all on your own Wi-Fi.
            </p>
          </header>

          <div class="grid gap-4 md:grid-cols-2 text-xs text-cyan-100/90">
            <div class="rounded border border-cyan-400/40 bg-black/60 p-3">
              <p class="text-[0.7rem] uppercase tracking-[0.18em] text-cyan-300">
                Live Pulse
              </p>
              <p class="mt-1">
                Internet Health gauge, latency &amp; jitter per target, and
                alerts when things get weird. Learn how a real NOC watches the
                WAN.
              </p>
            </div>
            <div class="rounded border border-cyan-400/40 bg-black/60 p-3">
              <p class="text-[0.7rem] uppercase tracking-[0.18em] text-cyan-300">
                Eye &amp; Brain
              </p>
              <p class="mt-1">
                Visual topology plus Smart Scripts that can run Nmap profiles,
                backups, reports, and packet manipulation experiments on networks you own.
              </p>
            </div>
            <div class="rounded border border-cyan-400/40 bg-black/60 p-3">
              <p class="text-[0.7rem] uppercase tracking-[0.18em] text-cyan-300">
                Vault
              </p>
              <p class="mt-1">
                Capture and replay PCAP slices, skim packet headers right in
                the UI, and download traces for deeper analysis.
              </p>
            </div>
            <div class="rounded border border-cyan-400/40 bg-black/60 p-3">
              <p class="text-[0.7rem] uppercase tracking-[0.18em] text-cyan-300">
                Built for learning
              </p>
              <p class="mt-1">
                Designed as a training ground: safe defaults, clear roles, and
                room to experiment before you step into a real job.
              </p>
            </div>
          </div>

          <footer class="mt-4 flex items-center justify-between text-[0.7rem]">
            <span class="font-mono text-cyan-200/80">
              Async backend · task queue · charts · network tools
            </span>
            <span class="text-cyan-300/80">
              A compact console for curious operators.
            </span>
          </footer>
        </div>
      </div>

      <div class="flex items-center">
        <div class="w-full">
          <Login @login-success="(token) => emit('login-success', token)" />
        </div>
      </div>
    </section>

    <!-- SysAdmin / enterprise-style landing -->
    <section
      v-else
      class="mx-auto grid w-full max-w-6xl gap-8 lg:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]"
    >
      <div class="flex flex-col justify-center gap-6">
        <div>
          <p class="text-[0.7rem] uppercase tracking-[0.3em] text-slate-500">
            Operations Console · SysAdmin Mode
          </p>
          <h2 class="mt-3 text-3xl font-semibold text-slate-900">
            A single, business-ready pane for network health and automation.
          </h2>
          <p class="mt-3 text-sm text-slate-600">
            NetPulse Enterprise gives you a practical view of connectivity,
            devices, and automation – suitable for a small team, lab, or
            internal SOC. Clear metrics, scripts, and reports you can trust.
          </p>
        </div>

        <div class="grid gap-4 md:grid-cols-2 text-xs text-slate-700">
          <div class="rounded-lg border border-slate-200 bg-white p-3 shadow-sm">
            <p class="text-[0.7rem] uppercase tracking-[0.18em] text-slate-500">
              Internet Health
            </p>
            <p class="mt-1">
              Summarised view of latency, jitter and packet loss across key
              targets, with alerts when thresholds are breached.
            </p>
          </div>
          <div class="rounded-lg border border-slate-200 bg-white p-3 shadow-sm">
            <p class="text-[0.7rem] uppercase tracking-[0.18em] text-slate-500">
              Device Inventory
            </p>
            <p class="mt-1">
              Passive discovery, Smart Scripts for inventory export and config
              backups, and drift reporting for switches and routers.
            </p>
          </div>
          <div class="rounded-lg border border-slate-200 bg-white p-3 shadow-sm">
            <p class="text-[0.7rem] uppercase tracking-[0.18em] text-slate-500">
              Automation &amp; Reporting
            </p>
            <p class="mt-1">
              Prebuilt WAN health and new-device reports, plus a controlled
              framework for running internal Python automation.
            </p>
          </div>
          <div class="rounded-lg border border-slate-200 bg-white p-3 shadow-sm">
            <p class="text-[0.7rem] uppercase tracking-[0.18em] text-slate-500">
              Built for teams
            </p>
            <p class="mt-1">
              Role-based access, script allowlists, and clear boundaries
              between lab-only experiments and production-safe actions.
            </p>
          </div>
        </div>

        <footer class="flex items-center justify-between text-[0.7rem] text-slate-500">
          <span>FastAPI · PostgreSQL/TimescaleDB · Redis/Celery · Vue 3</span>
          <span>
            A focused console for practical operations work.
          </span>
        </footer>
      </div>

      <div class="flex items-center">
        <div class="w-full">
          <Login @login-success="(token) => emit('login-success', token)" />
        </div>
      </div>
    </section>
  </div>
</template>