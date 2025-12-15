<script setup lang="ts">
import axios from "axios";
import { onMounted, ref } from "vue";

type Theme = "cyberdeck" | "sysadmin";
type InfoMode = "full" | "compact";

interface Props {
  theme: Theme;
  infoMode: InfoMode;
}

interface ScriptSettingsItem {
  name: string;
  allowed: boolean;
  lab_only: boolean;
}

const props = defineProps<Props>();

const emit = defineEmits<{
  (e: "update:infoMode", value: InfoMode): void;
}>();

function setInfoMode(mode: InfoMode): void {
  emit("update:infoMode", mode);
}

const scripts = ref<ScriptSettingsItem[]>([]);
const scriptsLoading = ref(false);
const scriptsError = ref<string | null>(null);
const savingScripts = ref(false);

async function loadScriptSettings(): Promise<void> {
  scriptsError.value = null;
  scriptsLoading.value = true;
  try {
    const { data } = await axios.get<{ scripts: ScriptSettingsItem[] }>(
      "/api/scripts/settings"
    );
    scripts.value = data.scripts ?? [];
  } catch {
    scriptsError.value =
      "Failed to load script allowlist. You may need admin permissions.";
  } finally {
    scriptsLoading.value = false;
  }
}

async function saveScriptSettings(): Promise<void> {
  if (!scripts.value.length) {
    return;
  }
  savingScripts.value = true;
  scriptsError.value = null;
  try {
    await axios.put("/api/scripts/settings", { scripts: scripts.value });
  } catch {
    scriptsError.value = "Failed to update script allowlist.";
  } finally {
    savingScripts.value = false;
  }
}

onMounted(() => {
  loadScriptSettings();
});
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
            <code class="font-mono">/api/...</code> (proxied to port 8000). You can
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
            <code class="font-mono">/api/...</code> (proxied to port 8000). Backend
            settings are controlled via environment variables / .env.
          </p>
        </div>

        <!-- Script allowlist configuration -->
        <div class="rounded-md border border-cyan-400/30 bg-black/50 p-3" v-if="theme === 'cyberdeck'">
          <p class="text-[0.7rem] uppercase tracking-[0.16em] text-cyan-200">
            Script allowlist
          </p>
          <p class="mt-1 text-[0.7rem] text-cyan-100/80">
            Control which prebuilt Smart Scripts can run from this console.
          </p>
          <div class="mt-2 text-[0.7rem]">
            <p v-if="scriptsLoading">Loading script settings...</p>
            <p v-else-if="scriptsError" class="text-rose-300">
              {{ scriptsError }}
            </p>
            <div v-else class="mt-1 max-h-48 overflow-auto rounded border border-cyan-400/20 bg-black/60">
              <table class="min-w-full text-[0.65rem]">
                <thead class="bg-black/70 text-cyan-200">
                  <tr>
                    <th class="px-2 py-1 text-left">Script</th>
                    <th class="px-2 py-1 text-center">Allowed</th>
                    <th class="px-2 py-1 text-center">Lab only</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="s in scripts"
                    :key="s.name"
                    class="border-t border-cyan-400/20 text-cyan-100"
                  >
                    <td class="px-2 py-1 font-mono">
                      {{ s.name }}
                    </td>
                    <td class="px-2 py-1 text-center">
                      <input
                        type="checkbox"
                        v-model="s.allowed"
                      />
                    </td>
                    <td class="px-2 py-1 text-center">
                      <input
                        type="checkbox"
                        v-model="s.lab_only"
                      />
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div class="mt-2 flex justify-end gap-2">
              <button
                type="button"
                @click="loadScriptSettings"
                class="rounded border border-cyan-400/40 px-2 py-0.5 text-[0.7rem] text-cyan-200 hover:bg-cyan-500/10"
              >
                Reload
              </button>
              <button
                type="button"
                @click="saveScriptSettings"
                class="rounded border border-emerald-400/60 bg-emerald-500/20 px-2 py-0.5 text-[0.7rem] text-emerald-200 disabled:opacity-50"
                :disabled="savingScripts"
              >
                {{ savingScripts ? "Saving..." : "Save changes" }}
              </button>
            </div>
          </div>
        </div>

        <div
          class="rounded-md border border-slate-200 bg-white p-3"
          v-else
        >
          <p class="text-[0.7rem] uppercase tracking-[0.16em] text-slate-500">
            Script allowlist
          </p>
          <p class="mt-1 text-[0.75rem] text-slate-600">
            Control which prebuilt Smart Scripts can run from this console.
          </p>
          <div class="mt-2 text-[0.75rem]">
            <p v-if="scriptsLoading">Loading script settings...</p>
            <p v-else-if="scriptsError" class="text-rose-500">
              {{ scriptsError }}
            </p>
            <div v-else class="mt-1 max-h-48 overflow-auto rounded border border-slate-200 bg-white">
              <table class="min-w-full text-[0.7rem]">
                <thead class="bg-slate-100 text-slate-700">
                  <tr>
                    <th class="px-2 py-1 text-left">Script</th>
                    <th class="px-2 py-1 text-center">Allowed</th>
                    <th class="px-2 py-1 text-center">Lab only</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="s in scripts"
                    :key="s.name"
                    class="border-t border-slate-200 text-slate-700"
                  >
                    <td class="px-2 py-1 font-mono">
                      {{ s.name }}
                    </td>
                    <td class="px-2 py-1 text-center">
                      <input
                        type="checkbox"
                        v-model="s.allowed"
                      />
                    </td>
                    <td class="px-2 py-1 text-center">
                      <input
                        type="checkbox"
                        v-model="s.lab_only"
                      />
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div class="mt-2 flex justify-end gap-2">
              <button
                type="button"
                @click="loadScriptSettings"
                class="rounded border border-slate-300 px-2 py-0.5 text-[0.7rem] text-slate-700 hover:bg-slate-100"
              >
                Reload
              </button>
              <button
                type="button"
                @click="saveScriptSettings"
                class="rounded border border-blue-500 bg-blue-50 px-2 py-0.5 text-[0.7rem] text-blue-700 disabled:opacity-50"
                :disabled="savingScripts"
              >
                {{ savingScripts ? "Saving..." : "Save changes" }}
              </button>
            </div>
          </div>
        </div>
      </div>
    </section>
  </div>
</template>