<script setup lang="ts">
import axios from "axios";
import { computed, onMounted, ref } from "vue";

type Role = "viewer" | "operator" | "admin";
type Theme = "cyberdeck" | "sysadmin";

interface Props {
  role: Role;
  theme: Theme;
}

interface ScriptSettingsItem {
  name: string;
  allowed: boolean;
}

interface Playbook {
  id: string;
  label: string;
  scriptName: string;
  description: string;
}

const props = defineProps<Props>();

const canRun = computed(() => props.role === "operator" || props.role === "admin");
const isCyberdeck = computed(() => props.theme === "cyberdeck");

// Script policy from backend
const scripts = ref<ScriptSettingsItem[]>([]);
const scriptsLoading = ref(false);
const scriptsError = ref<string | null>(null);

// Playbook selection and parameters
const allPlaybooks: Playbook[] = [
  {
    id: "syn-storm",
    label: "SYN storm",
    scriptName: "malformed_syn_flood.py",
    description:
      "Short SYN storm against a target to test IDS signatures and Internet Health alerts.",
  },
  {
    id: "xmas-scan",
    label: "Xmas scan",
    scriptName: "malformed_xmas_scan.py",
    description:
      "TCP Xmas scan-style packets across selected ports to exercise firewall / IDS behavior.",
  },
  {
    id: "overlap-fragments",
    label: "Overlapping fragments",
    scriptName: "malformed_overlap_fragments.py",
    description:
      "Tiny overlapping IP fragment pair to observe reassembly behavior and anomaly detection.",
  },
];

const selectedPlaybookId = ref<string | null>(allPlaybooks[0]?.id ?? null);
const targetIp = ref("");
const captureDuration = ref(60);
const runPdfReport = ref(true);

// Status
const running = ref(false);
const statusLines = ref<string[]>([]);
const pcapCaptureId = ref<number | null>(null);
const attackJobId = ref<number | null>(null);
const reportJobId = ref<number | null>(null);

function log(message: string): void {
  const now = new Date();
  const ts = now.toISOString().split("T")[1]?.slice(0, 8) ?? "";
  statusLines.value.push(`[${ts}] ${message}`);
}

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
      "Failed to load script policy. You may need to be logged in or have viewer permissions.";
  } finally {
    scriptsLoading.value = false;
  }
}

const availablePlaybooks = computed(() => {
  if (!scripts.value.length) {
    return allPlaybooks;
  }
  const allowedNames = new Set(
    scripts.value
      .filter((s) => s.allowed)
      .map((s) => s.name)
  );
  return allPlaybooks.filter((pb) => allowedNames.has(pb.scriptName));
});

const selectedPlaybook = computed<Playbook | null>(() => {
  const id = selectedPlaybookId.value;
  if (!id) return null;
  const list = availablePlaybooks.value.length ? availablePlaybooks.value : allPlaybooks;
  return list.find((pb) => pb.id === id) ?? null;
});

async function runPlaybookScenario(): Promise<void> {
  if (!canRun.value) {
    return;
  }
  const pb = selectedPlaybook.value;
  if (!pb) {
    log("Select a playbook first.");
    return;
  }
  if (!targetIp.value.trim()) {
    log("Enter a target IP or hostname first.");
    return;
  }

  running.value = true;
  statusLines.value = [];
  pcapCaptureId.value = null;
  attackJobId.value = null;
  reportJobId.value = null;

  log(`Playbook "${pb.label}" starting for target ${targetIp.value.trim()}`);

  try {
    // 1) Start PCAP capture window
    log(`Starting ${captureDuration.value}s capture window...`);
    const { data: captureTask } = await axios.post<{ task_id: string }>(
      "/api/vault/pcap/recent",
      {
        duration_seconds: captureDuration.value,
      }
    );
    const taskId = captureTask.task_id;

    // 2) Queue lab script
    log(`Queueing lab script ${pb.scriptName}...`);
    const attackPayload = {
      script_name: pb.scriptName,
      params: {
        target_ip: targetIp.value.trim(),
      },
    };
    const { data: attackJob } = await axios.post<{ job_id: number }>(
      "/api/scripts/prebuilt/run",
      attackPayload
    );
    attackJobId.value = attackJob.job_id;
    log(`Lab script queued (job #${attackJob.job_id}).`);

    // 3) Optionally queue WAN PDF report
    if (runPdfReport.value) {
      log("Queueing WAN PDF report...");
      try {
        const { data: reportJob } = await axios.post<{ job_id: number }>(
          "/api/scripts/prebuilt/run",
          {
            script_name: "wan_health_pdf_report.py",
            params: {},
          }
        );
        reportJobId.value = reportJob.job_id;
        log(`WAN PDF report queued (job #${reportJob.job_id}).`);
      } catch {
        log("Failed to queue WAN PDF report.");
      }
    }

    // 4) Poll capture status in the background
    const poll = async () => {
      try {
        const { data } = await axios.get<{
          ready: boolean;
          capture_id: number | null;
          state: string;
          error: string | null;
        }>(`/api/vault/pcap/task/${taskId}`);

        if (!data.ready) {
          log(`Capture state: ${data.state}`);
          setTimeout(poll, 5000);
          return;
        }

        if (data.error) {
          log(`Capture error: ${data.error}`);
          running.value = false;
          return;
        }

        if (data.capture_id != null) {
          pcapCaptureId.value = data.capture_id;
          log(`Capture ready (id ${data.capture_id}). Download from Vault panel.`);
          running.value = false;
        }
      } catch {
        log("Failed to query capture status.");
        running.value = false;
      }
    };

    setTimeout(poll, 5000);
  } catch {
    log("Failed to start playbook scenario. Check your permissions and script policy.");
    running.value = false;
  }
}

onMounted(() => {
  loadScriptSettings();
});
</script>

<template>
  <div class="grid gap-4 lg:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]">
    <section class="np-panel p-4 space-y-4">
      <header class="np-panel-header -mx-4 -mt-4 mb-2 px-4">
        <div class="flex flex-col">
          <span class="np-panel-title">Incident Playbooks</span>
          <span class="text-[0.7rem] text-[var(--np-muted-text)]">
            Chain a script, capture window, and optional report to rehearse an incident or test detection.
          </span>
        </div>
        <span
          class="text-[0.65rem] uppercase tracking-[0.16em]"
          :class="isCyberdeck ? 'text-cyan-300' : 'text-slate-500'"
        >
          Use on networks you own or control
        </span>
      </header>

      <div class="space-y-3 text-xs">
        <div
          class="rounded-md border p-3"
          :class="isCyberdeck ? 'border-cyan-400/30 bg-black/50' : 'border-slate-200 bg-white'"
        >
          <p
            class="text-[0.7rem] uppercase tracking-[0.16em]"
            :class="isCyberdeck ? 'text-cyan-200' : 'text-slate-600'"
          >
            Playbook
          </p>
          <p
            class="mt-1 text-[0.75rem]"
            :class="isCyberdeck ? 'text-cyan-100/80' : 'text-slate-600'"
          >
            Choose a scenario. Scripts must be present in the prebuilt scripts directory and allowed in Settings.
          </p>

          <div class="mt-2 grid gap-2 md:grid-cols-3">
            <button
              v-for="pb in availablePlaybooks"
              :key="pb.id"
              type="button"
              @click="selectedPlaybookId = pb.id"
              class="rounded border px-2 py-1 text-left text-[0.7rem]"
              :class="[
                selectedPlaybookId === pb.id
                  ? isCyberdeck
                    ? 'border-emerald-400/60 bg-emerald-500/20 text-emerald-200'
                    : 'border-blue-500 bg-blue-50 text-blue-700'
                  : isCyberdeck
                    ? 'border-cyan-400/40 text-cyan-200 hover:bg-cyan-500/10'
                    : 'border-slate-300 text-slate-700 hover:bg-slate-100'
              ]"
            >
              <span class="block font-semibold">{{ pb.label }}</span>
              <span
                class="mt-0.5 block text-[0.65rem]"
                :class="isCyberdeck ? 'text-cyan-100/80' : 'text-slate-500'"
              >
                {{ pb.description }}
              </span>
            </button>
          </div>

          <p
            v-if="!availablePlaybooks.length && !scriptsLoading"
            class="mt-2 text-[0.7rem]"
            :class="isCyberdeck ? 'text-amber-200' : 'text-amber-700'"
          >
            No playbook scripts are currently allowed. Enable them in Settings &gt; Script allowlist.
          </p>
        </div>

        <div
          class="rounded-md border p-3"
          :class="isCyberdeck ? 'border-cyan-400/30 bg-black/50' : 'border-slate-200 bg-white'"
        >
          <p
            class="text-[0.7rem] uppercase tracking-[0.16em]"
            :class="isCyberdeck ? 'text-cyan-200' : 'text-slate-600'"
          >
            Target &amp; capture window
          </p>
          <div class="mt-2 grid gap-3 md:grid-cols-[minmax(0,1.2fr)_minmax(0,0.8fr)]">
            <label class="text-[0.7rem] text-[var(--np-muted-text)]">
              Target (IP / Hostname)
              <input
                v-model="targetIp"
                type="text"
                class="mt-1 w-full rounded-md border px-2 py-1 text-[0.75rem]
                       focus:outline-none focus:ring-1"
                :class="isCyberdeck
                  ? 'border-cyan-400/40 bg-black/70 text-cyan-100 focus:ring-cyan-400'
                  : 'border-slate-300 bg-white text-slate-800 focus:ring-blue-500'"
                placeholder="10.0.0.5"
              />
            </label>

            <div class="space-y-1 text-[0.7rem]">
              <label class="block text-[var(--np-muted-text)]">
                Capture duration (seconds)
                <input
                  v-model.number="captureDuration"
                  type="number"
                  min="10"
                  max="600"
                  step="10"
                  class="mt-1 w-full rounded-md border px-2 py-1 text-[0.75rem]
                         focus:outline-none focus:ring-1"
                  :class="isCyberdeck
                    ? 'border-cyan-400/40 bg-black/70 text-cyan-100 focus:ring-cyan-400'
                    : 'border-slate-300 bg-white text-slate-800 focus:ring-blue-500'"
                />
              </label>
              <label class="flex items-center gap-2 text-[0.7rem]">
                <input type="checkbox" v-model="runPdfReport" />
                <span>Queue WAN PDF report alongside scenario</span>
              </label>
            </div>
          </div>

          <div class="mt-3 flex items-center justify-between text-[0.7rem]">
            <div
              :class="isCyberdeck ? 'text-cyan-100/80' : 'text-slate-600'"
            >
              <p v-if="canRun">
                Playbooks can generate aggressive or malformed traffic. Use only on networks you own or control.
              </p>
              <p v-else>
                You have viewer access. Playbooks require operator or admin role.
              </p>
            </div>
            <button
              type="button"
              @click="runPlaybookScenario"
              class="rounded border px-3 py-1.5 text-[0.75rem] font-medium"
              :class="[
                canRun
                  ? isCyberdeck
                    ? 'border-emerald-400/60 bg-emerald-500/20 text-emerald-200 hover:bg-emerald-500/30'
                    : 'border-blue-500 bg-blue-50 text-blue-700 hover:bg-blue-100'
                  : 'border-slate-300 text-slate-500 cursor-not-allowed'
              ]"
              :disabled="running || !canRun"
            >
              {{ running ? "Running scenario..." : "Run playbook" }}
            </button>
          </div>
        </div>
      </div>
    </section>

    <section class="np-panel p-4 space-y-4">
      <header class="np-panel-header -mx-4 -mt-4 mb-2 px-4">
        <div class="flex flex-col">
          <span class="np-panel-title">Scenario Timeline</span>
          <span class="text-[0.7rem] text-[var(--np-muted-text)]">
            Follow capture state, script jobs, and report generation.
          </span>
        </div>
      </header>

      <div class="space-y-3 text-xs">
        <div
          class="rounded-md border p-3"
          :class="isCyberdeck ? 'border-cyan-400/30 bg-black/60' : 'border-slate-200 bg-white'"
        >
          <p
            class="text-[0.7rem] uppercase tracking-[0.16em]"
            :class="isCyberdeck ? 'text-cyan-200' : 'text-slate-600'"
          >
            Status
          </p>
          <div
            class="mt-2 h-40 overflow-auto rounded border text-[0.7rem] font-mono"
            :class="isCyberdeck ? 'border-cyan-400/20 bg-black/80 text-cyan-100' : 'border-slate-200 bg-slate-50 text-slate-800'"
          >
            <div v-if="!statusLines.length" class="p-2 opacity-70">
              Waiting for a playbook run. When you start a scenario, progress will appear here.
            </div>
            <pre v-else class="whitespace-pre-wrap break-words p-2">
{{ statusLines.join('\n') }}
            </pre>
          </div>
        </div>

        <div class="grid gap-3 md:grid-cols-3">
          <div
            class="rounded-md border p-3"
            :class="isCyberdeck ? 'border-cyan-400/30 bg-black/60' : 'border-slate-200 bg-white'"
          >
            <p class="text-[0.7rem] uppercase tracking-[0.16em] text-[var(--np-muted-text)]">
              PCAP capture
            </p>
            <p class="mt-1 text-[0.7rem]">
              <span v-if="pcapCaptureId != null">
                Capture ready with id
                <span class="font-mono">#{{ pcapCaptureId }}</span>. Open Vault to download and inspect.
              </span>
              <span v-else>
                No capture completed yet for this session.
              </span>
            </p>
          </div>
          <div
            class="rounded-md border p-3"
            :class="isCyberdeck ? 'border-cyan-400/30 bg-black/60' : 'border-slate-200 bg-white'"
          >
            <p class="text-[0.7rem] uppercase tracking-[0.16em] text-[var(--np-muted-text)]">
              Lab script job
            </p>
            <p class="mt-1 text-[0.7rem]">
              <span v-if="attackJobId != null">
                Lab script queued as job
                <span class="font-mono">#{{ attackJobId }}</span>. Logs are available via the script job API or future console integration.
              </span>
              <span v-else>
                No lab script queued yet for this session.
              </span>
            </p>
          </div>
          <div
            class="rounded-md border p-3"
            :class="isCyberdeck ? 'border-cyan-400/30 bg-black/60' : 'border-slate-200 bg-white'"
          >
            <p class="text-[0.7rem] uppercase tracking-[0.16em] text-[var(--np-muted-text)]">
              WAN PDF report
            </p>
            <p class="mt-1 text-[0.7rem]">
              <span v-if="runPdfReport && reportJobId != null">
                WAN PDF report queued as job
                <span class="font-mono">#{{ reportJobId }}</span>. Retrieve the artifact from the Vault/reporting workflow.
              </span>
              <span v-else-if="runPdfReport">
                Report has not been queued yet for this session.
              </span>
              <span v-else>
                WAN PDF report is disabled for this playbook run.
              </span>
            </p>
          </div>
        </div>

        <div
          class="rounded-md border p-3"
          :class="isCyberdeck ? 'border-cyan-400/30 bg-black/60' : 'border-slate-200 bg-white'"
        >
          <p class="text-[0.7rem] uppercase tracking-[0.16em] text-[var(--np-muted-text)]">
            Safety note
          </p>
          <p class="mt-1 text-[0.7rem]" :class="isCyberdeck ? 'text-cyan-100/80' : 'text-slate-600'">
            These playbooks can generate malformed or aggressive packets. Use them responsibly on
            networks and systems you own or are explicitly authorised to test.
          </p>
        </div>
      </div>
    </section>
  </div>
</template>