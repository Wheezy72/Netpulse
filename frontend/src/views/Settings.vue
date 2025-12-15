<script setup lang="ts">
type Theme = "cyberdeck" | "sysadmin";
type InfoMode = "full" | "compact";

interface Props {
  theme: Theme;
  infoMode: InfoMode;
}

const props = defineProps<Props>();

const emit = defineEmits<{
  (e: "update:infoMode", value: InfoMode): void;
}>();

function setInfoMode(mode: InfoMode): void {
  emit("update:infoMode", mode);
}
</script>

<template>
  <div class="grid gap-4 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
    <section class="np-panel p-4 space-y-4">
      <header class="np-panel-header -mx-4 -mt-4 mb-2 px-4">
        <div class="flex flex-col">
          <span class="np-panel-title">Console Settings</span>
          <span class="text-[0.7rem] text-[var(--np-muted-text)]">
            Tune how dense the dashboard feels.
          </span>
        </div>
      </header>

      <div class="space-y-3 text-xs">
        <div class="rounded-md border border-cyan-400/30 bg-black/50 p-3" v-if="theme === 'cyberdeck'">
          <p class="text-[0.7rem] uppercase tracking-[0.16em] text-cyan-200">
            View Density
          </p>
          <p class="mt-1 text-[0.7rem] text-cyan-100/80">
            Choose between a detailed operator console and a quick-look mode.
          </p>
          <div class="mt-2 flex flex-wrap gap-2 text-[0.7rem]">
            <button
              type="button"
              @click="setInfoMode('full')"
              class="rounded border px-2 py-1"
              :class="[
                infoMode === 'full'
                  ? 'border-emerald-400/60 bg-emerald-500/20 text-emerald-300'
                  : 'border-cyan-400/40 text-cyan-200 hover:bg-cyan-500/10'
              ]"
            >
              Full detail
            </button>
            <button
              type="button"
              @click="setInfoMode('compact')"
              class="rounded border px-2 py-1"
              :class="[
                infoMode === 'compact'
                  ? 'border-emerald-400/60 bg-emerald-500/20 text-emerald-300'
                  : 'border-cyan-400/40 text-cyan-200 hover:bg-cyan-500/10'
              ]"
            >
              Quick view
            </button>
          </div>
          <p class="mt-2 text-[0.7rem] text-cyan-100/70">
            The Pulse chart and Vault controls adapt to this setting.
          </p>
        </div>

        <div
          class="rounded-md border border-slate-200 bg-white p-3"
          v-else
        >
          <p class="text-[0.7rem] uppercase tracking-[0.16em] text-slate-500">
            View Density
          </p>
          <p class="mt-1 text-[0.75rem] text-slate-600">
            Choose how much context is shown on the dashboard.
          </p>
          <div class="mt-2 flex flex-wrap gap-2 text-[0.7rem]">
            <button
              type="button"
              @click="setInfoMode('full')"
              class="rounded border px-2 py-1"
              :class="[
                infoMode === 'full'
                  ? 'border-blue-500 bg-blue-50 text-blue-700'
                  : 'border-slate-300 text-slate-700 hover:bg-slate-100'
              ]"
            >
              Full detail
            </button>
            <button
              type="button"
              @click="setInfoMode('compact')"
              class="rounded border px-2 py-1"
              :class="[
                infoMode === 'compact'
                  ? 'border-blue-500 bg-blue-50 text-blue-700'
                  : 'border-slate-300 text-slate-700 hover:bg-slate-100'
              ]"
            >
              Quick view
            </button>
          </div>
        </div>

        <div class="rounded-md border border-cyan-400/30 bg-black/50 p-3" v-if="theme === 'cyberdeck'">
          <p class="text-[0.7rem] uppercase tracking-[0.16em] text-cyan-200">
            Live telemetry
          </p>
          <p class="mt-1 text-[0.7rem] text-cyan-100/80">
            Pulse and topology auto-refresh in the background. For very small labs, you can
            disable the worker services to pause collection.
          </p>
        </div>

        <div
          class="rounded-md border border-slate-200 bg-white p-3"
          v-else
        >
          <p class="text-[0.7rem] uppercase tracking-[0.16em] text-slate-500">
            Live telemetry
          </p>
          <p class="mt-1 text-[0.75rem] text-slate-600">
            Pulse and topology auto-refresh periodically. Control scheduling from your
            infrastructure (Celery beat / crontab).
          </p>
        </div>
      </div>
    </section>

    <section class="np-panel p-4 space-y-4">
      <header class="np-panel-header -mx-4 -mt-4 mb-2 px-4">
        <div class="flex flex-col">
          <span class="np-panel-title">Environment</span>
          <span class="text-[0.7rem] text-[var(--np-muted-text)]">
            Quick reference for how this instance is wired.
          </span>
        </div>
      </header>

      <div class="space-y-3 text-xs">
        <div class="rounded-md border border-cyan-400/30 bg-black/50 p-3" v-if="theme === 'cyberdeck'">
          <p class="text-[0.7rem] uppercase tracking-[0.16em] text-cyan-200">
            Console Theme
          </p>
          <p class="mt-1 text-[0.7rem] text-cyan-100/80">
            Active mode:
            <span class="font-semibold">
              {{ theme === "cyberdeck" ? "CyberDeck" : "SysAdmin Pro" }}
            </span>.
            Use the toggle in the header to switch between them.
          </p>
        </div>

        <div
          class="rounded-md border border-slate-200 bg-white p-3"
          v-else
        >
          <p class="text-[0.7rem] uppercase tracking-[0.16em] text-slate-500">
            Console Theme
          </p>
          <p class="mt-1 text-[0.75rem] text-slate-600">
            Active mode:
            <span class="font-semibold">
              {{ theme === "cyberdeck" ? "CyberDeck" : "SysAdmin Pro" }}
            </span>.
            Use the toggle in the header to switch between them.
          </p>
        </div>

        <div class="rounded-md border border-cyan-400/30 bg-black/50 p-3" v-if="theme === 'cyberdeck'">
          <p class="text-[0.7rem] uppercase tracking-[0.16em] text-cyan-200">
            Backend endpoints
          </p>
          <p class="mt-1 text-[0.7rem] text-cyan-100/80">
            The frontend talks to the API at
            <code class="font-mono">/api/…</code> (proxied to port 8000). You can
            change base URLs and script allowlists via the backend configuration.
          </p>
        </div>

        <div
          class="rounded-md border border-slate-200 bg-white p-3"
          v-else
        >
          <p class="text-[0.7rem] uppercase tracking-[0.16em] text-slate-500">
            Backend endpoints
          </p>
          <p class="mt-1 text-[0.75rem] text-slate-600">
            The frontend talks to the API at
            <code class="font-mono">/api/…</code> (proxied to port 8000). Backend
            settings are controlled via environment variables / .env.
          </p>
        </div>
      </div>
    </section>
  </div>
</template>