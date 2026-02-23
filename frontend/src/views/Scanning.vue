<script setup lang="ts">
import axios from "axios";
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";

import LiveTerminal from "../components/LiveTerminal.vue";

type Theme = "nightshade" | "sysadmin";

const props = defineProps<{ theme: Theme; isAdmin: boolean }>();
const emit = defineEmits<{ (e: "toast", type: "success" | "error" | "warning" | "info", message: string): void }>();

type Playbook = {
  id: string;
  name: string;
  description: string;
  category: string;
  nmap_args: string;
  ports?: string | null;
  scripts?: string[] | null;
  recommended_for: string[];
  risk_level: string;
  estimated_time: string;
};

type Tab = "targeted" | "playbooks";
const activeTab = ref<Tab>("targeted");

const target = ref<string>("");

type TargetedPresetId = "ping" | "quick" | "services" | "full" | "vuln" | "custom";
const preset = ref<TargetedPresetId>("quick");
const customCommand = ref<string>("nmap -sV -sC -T4");
const saveResults = ref<boolean>(true);

const playbooks = ref<Playbook[]>([]);
const playbooksLoading = ref(false);
const selectedPlaybookId = ref<string>("");

const currentScanId = ref<string | null>(null);

type ScanMeta = {
  id: string;
  status: string;
  result_summary?: Record<string, any> | null;
  ai_briefing?: string | null;
  completed_at?: string | null;
};

const scanMeta = ref<ScanMeta | null>(null);
const scanMetaLoading = ref(false);

let scanPollTimer: number | null = null;

function getWsBase(): string {
  const apiBase = (import.meta as any).env?.VITE_API_BASE_URL || window.location.origin;
  return String(apiBase).replace(/^http/, "ws");
}

const terminalTitle = computed(() => (currentScanId.value ? `Scan ${currentScanId.value}` : "Scan Output"));
const terminalStreamUrl = computed(() => {
  if (!currentScanId.value) return null;
  const token = localStorage.getItem("np-token");
  if (!token) return null;
  return `${getWsBase()}/api/ws/scans/${currentScanId.value}?token=${encodeURIComponent(token)}`;
});

const downloadUrl = computed(() => {
  if (!currentScanId.value) return null;
  const filename = `scan_${currentScanId.value}.txt`;
  return `/api/nmap/files/${filename}`;
});

const aiBriefing = computed(() => scanMeta.value?.ai_briefing || null);
const aiError = computed(() => (scanMeta.value?.result_summary as any)?.ai_error || null);

const selectedPlaybook = computed(() => playbooks.value.find((p) => p.id === selectedPlaybookId.value) || null);

async function fetchScanMeta(): Promise<void> {
  if (!currentScanId.value) return;
  scanMetaLoading.value = true;
  try {
    const { data } = await axios.get<ScanMeta>(`/api/nmap/result/${currentScanId.value}`, {
      params: { include_output: false },
    });
    scanMeta.value = data;
  } catch {
    // ignore transient polling errors
  } finally {
    scanMetaLoading.value = false;
  }
}

function stopScanPolling(): void {
  if (scanPollTimer) {
    window.clearInterval(scanPollTimer);
    scanPollTimer = null;
  }
}

function startScanPolling(): void {
  stopScanPolling();
  scanMeta.value = null;
  void fetchScanMeta();
  scanPollTimer = window.setInterval(async () => {
    await fetchScanMeta();
    const meta = scanMeta.value;
    if (!meta) return;

    const done = meta.status === "completed" || meta.status === "failed";
    if (done && (meta.ai_briefing || meta.result_summary)) {
      stopScanPolling();
    }
  }, 2000);
}

function commandForPreset(p: TargetedPresetId): string {
  switch (p) {
    case "ping":
      return "nmap -sn -T4";
    case "quick":
      return "nmap -T4 -F";
    case "services":
      return "nmap -sV -sC -T4";
    case "full":
      return "nmap -sS -sV -p- -T4 --min-rate=1000";
    case "vuln":
      return "nmap -sV --script=vuln --script-timeout=60s";
    case "custom":
      return customCommand.value;
  }
}

async function startScan(command: string): Promise<void> {
  if (!props.isAdmin) {
    emit("toast", "warning", "Admin access required to run scans.");
    return;
  }

  if (!target.value.trim()) {
    emit("toast", "warning", "Please enter a target (IP, hostname, or CIDR)." );
    return;
  }

  try {
    const { data } = await axios.post<{ id: string }>("/api/nmap/execute", {
      command,
      target: target.value.trim(),
      save_results: saveResults.value,
    });

    currentScanId.value = data.id;
    emit("toast", "success", `Scan started: ${data.id}`);
  } catch (e: any) {
    emit("toast", "error", e?.response?.data?.detail || e?.message || "Failed to start scan");
  }
}

async function runTargeted(): Promise<void> {
  await startScan(commandForPreset(preset.value));
}

async function runPlaybook(): Promise<void> {
  if (!selectedPlaybook.value) {
    emit("toast", "warning", "Select a playbook first.");
    return;
  }

  const pb = selectedPlaybook.value;

  let cmd = `nmap ${pb.nmap_args}`.trim();

  if (pb.ports && !cmd.includes("-p")) {
    cmd = `${cmd} -p ${pb.ports}`.trim();
  }

  if (pb.scripts && pb.scripts.length > 0 && !cmd.includes("--script")) {
    cmd = `${cmd} --script=${pb.scripts.join(",")}`.trim();
  }

  await startScan(cmd);
}

async function loadPlaybooks(): Promise<void> {
  playbooksLoading.value = true;
  try {
    const { data } = await axios.get<Playbook[]>("/api/playbooks/");
    playbooks.value = data;
    if (!selectedPlaybookId.value && data.length > 0) {
      selectedPlaybookId.value = data[0].id;
    }
  } catch {
    emit("toast", "error", "Failed to load playbooks");
  } finally {
    playbooksLoading.value = false;
  }
}

onMounted(() => {
  loadPlaybooks();
});

watch(
  () => currentScanId.value,
  (next) => {
    if (next) {
      startScanPolling();
    } else {
      stopScanPolling();
      scanMeta.value = null;
    }
  }
);

onBeforeUnmount(() => {
  stopScanPolling();
});
</script>

<template>
  <div class="grid grid-cols-1 xl:grid-cols-2 gap-6">
    <div class="space-y-6">
      <div class="np-panel">
        <div class="flex items-center justify-between px-4 py-3 border-b" :style="{ borderColor: 'var(--np-border)' }">
          <div>
            <h2 class="np-panel-title">Scanning Console</h2>
            <p class="text-xs text-[var(--np-muted-text)] mt-1">Run targeted scans or automated playbooks. Output streams live.</p>
          </div>
        </div>

        <div class="p-4 space-y-4">
          <div
            v-if="!props.isAdmin"
            class="rounded-lg border px-3 py-2 text-xs"
            :style="{ borderColor: 'var(--np-border)', background: 'var(--np-surface)' }"
          >
            <p class="text-[var(--np-muted-text)]">
              Scanning is <span class="font-semibold text-[var(--np-text)]">admin-only</span>.
              You can view scan output and history, but cannot start new scans.
            </p>
          </div>
         < div
            v-if="!props.isAdmin"
            class="rounded-lg border px-3 py-2 text-xs"
            :">
          <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div class="md:col-span-2">
              <label class="block text-[0.7rem] uppercase tracking-widest text-[var(--np-muted-text)]">Target</label>
              <input
                v-model="target"
                type="text"
                placeholder="192.168.1.1 or 192.168.1.0/24 or example.com"
                class="mt-1 w-full px-3 py-2 rounded-lg text-sm bg-transparent border outline-none border-[var(--np-border)] text-[var(--np-text)] placeholder:text-[var(--np-muted-text)] focus:border-[var(--np-accent-primary)]"
              />
            </div>

            <div>
              <label class="block text-[0.7rem] uppercase tracking-widest text-[var(--np-muted-text)]">Artifacts</label>
              <div class="mt-1 flex items-center gap-2">
                <input id="save" v-model="saveResults" type="checkbox" class="rounded" />
                <label for="save" class="text-xs text-[var(--np-muted-text)]">Save output</label>
              </div>
              <a
                v-if="downloadUrl"
                :href="downloadUrl"
                class="mt-2 inline-block text-xs underline text-[var(--np-accent-primary)] hover:opacity-90"
              >
                Download latest
              </a>
            </div>
          </div>

          <div class="flex items-center gap-2">
            <button
              type="button"
              class="px-3 py-2 rounded-lg text-xs border transition-colors"
              :class="[
                activeTab === 'targeted'
                  ? 'border-[var(--np-accent-primary)] text-[var(--np-text)] bg-[var(--np-bg)]'
                  : 'border-transparent text-[var(--np-muted-text)] hover:text-[var(--np-text)] hover:border-[var(--np-border)]'
              ]"
              @click="activeTab = 'targeted'"
            >
              Targeted Scans
            </button>
            <button
              type="button"
              class="px-3 py-2 rounded-lg text-xs border transition-colors"
              :class="[
                activeTab === 'playbooks'
                  ? 'border-[var(--np-accent-primary)] text-[var(--np-text)] bg-[var(--np-bg)]'
                  : 'border-transparent text-[var(--np-muted-text)] hover:text-[var(--np-text)] hover:border-[var(--np-border)]'
              ]"
              @click="activeTab = 'playbooks'"
            >
              Automated Playbooks
            </button>
          </div>

          <div v-if="activeTab === 'targeted'" class="space-y-4">
            <div>
              <label class="block text-[0.7rem] uppercase tracking-widest text-[var(--np-muted-text)]">Preset</label>
              <select
                v-model="preset"
                class="mt-1 w-full px-3 py-2 rounded-lg text-sm bg-transparent border outline-none border-[var(--np-border)] text-[var(--np-text)] focus:border-[var(--np-accent-primary)]"
              >
                <option value="ping">Ping Sweep (-sn)</option>
                <option value="quick">Quick Ports (-F)</option>
                <option value="services">Services & Scripts (-sV -sC)</option>
                <option value="full">Full Port Scan (-p-)</option>
                <option value="vuln">Vulnerability Scripts (--script=vuln)</option>
                <option value="custom">Custom</option>
              </select>
            </div>

            <div v-if="preset === 'custom'">
              <label class="block text-[0.7rem] uppercase tracking-widest text-[var(--np-muted-text)]">Command</label>
              <input
                v-model="customCommand"
                type="text"
                class="mt-1 w-full px-3 py-2 rounded-lg text-sm bg-transparent border outline-none border-[var(--np-border)] text-[var(--np-text)] placeholder:text-[var(--np-muted-text)] focus:border-[var(--np-accent-primary)]"
                placeholder="nmap -sV -sC -T4"
              />
              <p class="mt-1 text-[0.7rem] text-[var(--np-muted-text)]">Only an allowlist of flags/scripts is permitted.</p>
            </div>

            <div class="flex justify-end">
              <button
                type="button"
                @click="runTargeted"
                :disabled="!props.isAdmin"
                class="px-4 py-2 rounded-lg text-xs font-semibold transition-colors border border-[var(--np-accent-primary)] text-[var(--np-text)] hover:bg-[var(--np-bg)] disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Run Scan
              </button>
            </div>
          </div>

          <div v-else class="space-y-4">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label class="block text-[0.7rem] uppercase tracking-widest text-[var(--np-muted-text)]">Playbook</label>
                <select
                  v-model="selectedPlaybookId"
                  class="mt-1 w-full px-3 py-2 rounded-lg text-sm bg-transparent border outline-none border-[var(--np-border)] text-[var(--np-text)] focus:border-[var(--np-accent-primary)] disabled:opacity-50"
                  :disabled="playbooksLoading"
                >
                  <option v-for="pb in playbooks" :key="pb.id" :value="pb.id">
                    {{ pb.category }} — {{ pb.name }}
                  </option>
                </select>
              </div>

              <div class="flex items-end justify-end">
                <button
                  type="button"
                  @click="runPlaybook"
                  class="px-4 py-2 rounded-lg text-xs font-semibold transition-colors border border-[var(--np-accent-primary)] text-[var(--np-text)] hover:bg-[var(--np-bg)] disabled:opacity-50 disabled:cursor-not-allowed"
                  :disabled="!props.isAdmin || !selectedPlaybook || playbooksLoading"
                >
                  Run Playbook
                </button>
              </div>
            </div>

            <div v-if="selectedPlaybook" class="rounded-lg border p-3 border-[var(--np-border)] bg-[var(--np-bg)]">
              <div class="flex items-center justify-between">
                <div>
                  <p class="text-sm font-semibold text-[var(--np-text)]">{{ selectedPlaybook.name }}</p>
                  <p class="text-xs text-[var(--np-muted-text)]">{{ selectedPlaybook.description }}</p>
                </div>
                <div class="text-right">
                  <p class="text-[0.7rem] uppercase tracking-widest text-[var(--np-accent-primary)]">{{ selectedPlaybook.risk_level }}</p>
                  <p class="text-[0.7rem] text-[var(--np-muted-text)]">{{ selectedPlaybook.estimated_time }}</p>
                </div>
              </div>

              <p class="mt-3 text-[0.7rem] text-[var(--np-muted-text)]">Command template: <span class="font-mono">{{ selectedPlaybook.nmap_args }}</span></p>
            </div>
          </div>
        </div>
      </div>

      <div class="np-panel">
        <div class="px-4 py-3 border-b" :style="{ borderColor: 'var(--np-border)' }">
          <h3 class="np-panel-title">Tips</h3>
        </div>
        <div class="p-4 text-xs text-[var(--np-muted-text)] space-y-2">
          <p>• Use <span class="font-mono">Ping Sweep</span> or <span class="font-mono">Quick Ports</span> first to avoid noisy scans.</p>
          <p>• Full scans and vuln scripts may trigger IDS/IPS. Only scan networks you own or control.</p>
          <p>• Output files are stored as <span class="font-mono">data/scans/scan_&lt;id&gt;.txt</span>.</p>
        </div>
      </div>
    </div>

    <div class="h-[70vh] xl:h-[calc(100vh-9rem)] flex flex-col gap-4">
      <div class="np-panel">
        <div class="flex items-center justify-between px-4 py-3 border-b" :style="{ borderColor: 'var(--np-border)' }">
          <h3 class="np-panel-title">AI Analyst Briefing</h3>
          <div class="text-[0.7rem] text-[var(--np-muted-text)]">
            <span v-if="!currentScanId">Idle</span>
            <span v-else-if="scanMetaLoading">Analyzing…</span>
            <span v-else>Auto</span>
          </div>
        </div>
        <div class="p-4">
          <p v-if="!currentScanId" class="text-xs text-[var(--np-muted-text)]">Run a scan to generate an automatic analyst summary.</p>
          <p v-else-if="aiBriefing" class="text-sm leading-relaxed whitespace-pre-wrap text-[var(--np-text)]">{{ aiBriefing }}</p>
          <p v-else-if="aiError" class="text-xs text-[var(--np-danger)]">AI analysis failed: {{ aiError }}</p>
          <p v-else class="text-xs text-[var(--np-muted-text)]">Waiting for scan completion and AI analysis…</p>
        </div>
      </div>

      <div class="flex-1 min-h-0">
        <LiveTerminal :title="terminalTitle" :stream-url="terminalStreamUrl" :theme="props.theme" />
      </div>
    </div>
  </div>
</template>
