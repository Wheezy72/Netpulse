<script setup lang="ts">
import axios from "axios";
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import LiveTerminal from "../components/features/LiveTerminal.vue";

type Theme = "nightshade" | "sysadmin";

interface Props {
  theme: Theme;
  isAdmin: boolean;
}

const props = defineProps<Props>();
const emit = defineEmits<{ (e: "toast", type: "success" | "error" | "warning" | "info", message: string): void }>();

const isNightshade = computed(() => props.theme === "nightshade");

// --- Tab Management ---
type ActiveTab = "scanning" | "diagnostics" | "automation";
const activeTab = ref<ActiveTab>("scanning");

// --- General State ---
const target = ref("");
const saveResults = ref(true);
const isTerminalOpen = ref(false);

// --- Scanning State ---
type TargetedPresetId = "ping" | "quick" | "services" | "full" | "vuln" | "custom";
const preset = ref<TargetedPresetId>("quick");
const customCommand = ref("nmap -sV -sC -T4");

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

const playbooks = ref<Playbook[]>([]);
const playbooksLoading = ref(false);
const selectedPlaybookId = ref("");
const selectedPlaybook = computed(() => playbooks.value.find((p) => p.id === selectedPlaybookId.value) || null);

const currentScanId = ref<string | null>(null);
const scanMeta = ref<{ id: string; status: string; ai_briefing?: string | null; result_summary?: Record<string, any> | null } | null>(null);
const scanMetaLoading = ref(false);
let scanPollTimer: number | null = null;

// --- Diagnostics State (TCP & MTR) ---
const tcpHost = ref("");
const tcpPort = ref(80);
const tcpTesting = ref(false);
const tcpResult = ref<{ latency_ms: number | null; error: string | null } | null>(null);

interface MtrHop {
  hop: number;
  host: string;
  loss_pct: number;
  avg_ms: number;
  best_ms: number;
  worst_ms: number;
}

const mtrTarget = ref("8.8.8.8");
const mtrActive = ref(false);
const mtrHops = ref<MtrHop[]>([]);
const mtrError = ref<string | null>(null);
let mtrWs: WebSocket | null = null;

// --- Automation State ---
type PrebuiltScript = { name: string; allowed: boolean };
const availableScripts = ref<PrebuiltScript[]>([]);
const selectedScript = ref("");
const scriptParams = ref("{}");
const runningScriptJobId = ref<number | null>(null);
const scriptJobStatus = ref<string | null>(null);
const scriptLogs = ref<string | null>(null);
let scriptPollTimer: number | null = null;

// --- Terminal WebSockets ---
function getWsBase(): string {
  const apiBase = (import.meta as any).env?.VITE_API_BASE_URL || window.location.origin;
  return String(apiBase).replace(/^http/, "ws");
}

const terminalTitle = computed(() => (currentScanId.value ? `Scan ${currentScanId.value}` : "Toolbox Output Console"));
const terminalStreamUrl = computed(() => {
  if (!currentScanId.value) return null;
  const token = localStorage.getItem("np-token");
  if (!token) return null;
  return `${getWsBase()}/api/ws/scans/${currentScanId.value}?token=${encodeURIComponent(token)}`;
});

const downloadUrl = computed(() => {
  if (!currentScanId.value) return null;
  return `/api/nmap/files/scan_${currentScanId.value}.txt`;
});

async function downloadLatest(): Promise<void> {
  if (!downloadUrl.value || !currentScanId.value) return;
  try {
    const response = await axios.get(downloadUrl.value, { responseType: "blob" });
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement("a");
    link.href = url;
    link.download = `scan_${currentScanId.value}.txt`;
    link.click();
    window.URL.revokeObjectURL(url);
  } catch (e: any) {
    emit("toast", "error", e?.response?.data?.detail || "Failed to download scan output");
  }
}

// --- Polling Scans ---
function stopScanPolling(): void {
  if (scanPollTimer) {
    window.clearInterval(scanPollTimer);
    scanPollTimer = null;
  }
}

function startScanPolling(): void {
  stopScanPolling();
  scanPollTimer = window.setInterval(async () => {
    if (!currentScanId.value) return;
    try {
      const { data } = await axios.get(`/api/nmap/result/${currentScanId.value}`, {
        params: { include_output: false },
      });
      scanMeta.value = data;
      if (data.status === "completed" || data.status === "failed") {
        stopScanPolling();
        emit("toast", "success", `Scan ${currentScanId.value} completed!`);
      }
    } catch {
      // ignore transient polling errors
    }
  }, 2000);
}

// --- Execute Nmap Scan ---
async function startScan(command: string): Promise<void> {
  if (!props.isAdmin) {
    emit("toast", "warning", "Admin access required to run scans.");
    return;
  }
  if (!target.value.trim()) {
    emit("toast", "warning", "Please enter a target (IP or hostname).");
    return;
  }

  try {
    const { data } = await axios.post<{ id: string }>("/api/nmap/execute", {
      command,
      target: target.value.trim(),
      save_results: saveResults.value,
    });
    currentScanId.value = data.id;
    isTerminalOpen.value = true;
    startScanPolling();
    emit("toast", "success", `Scan initialized: ${data.id}`);
  } catch (e: any) {
    emit("toast", "error", e?.response?.data?.detail || "Failed to start scan");
  }
}

function commandForPreset(p: TargetedPresetId): string {
  switch (p) {
    case "ping": return "nmap -sn -T4";
    case "quick": return "nmap -T4 -F";
    case "services": return "nmap -sV -sC -T4";
    case "full": return "nmap -sS -sV -p- -T4 --min-rate=1000";
    case "vuln": return "nmap -sV --script=vuln --script-timeout=60s";
    case "custom": return customCommand.value;
  }
}

async function runTargeted(): Promise<void> {
  await startScan(commandForPreset(preset.value));
}

async function runPlaybook(): Promise<void> {
  if (!selectedPlaybook.value) return;
  const pb = selectedPlaybook.value;
  let cmd = `nmap ${pb.nmap_args}`.trim();
  if (pb.ports && !cmd.includes("-p")) cmd = `${cmd} -p ${pb.ports}`;
  if (pb.scripts && pb.scripts.length > 0 && !cmd.includes("--script")) {
    cmd = `${cmd} --script=${pb.scripts.join(",")}`;
  }
  await startScan(cmd);
}

// --- Execute Diagnostics ---
async function runTcpTest(): Promise<void> {
  const host = tcpHost.value.trim();
  if (!host) return;
  tcpTesting.value = true;
  tcpResult.value = null;
  try {
    const { data } = await axios.post<{ latency_ms: number | null; error: string | null }>(
      "/api/insights/tcp-probe",
      { host, port: tcpPort.value }
    );
    tcpResult.value = data;
  } catch (err: any) {
    tcpResult.value = {
      latency_ms: null,
      error: err?.response?.data?.detail ?? "TCP probe failed.",
    };
  } finally {
    tcpTesting.value = false;
  }
}

function startMtr(): void {
  stopMtr();
  mtrHops.value = [];
  mtrError.value = null;
  mtrActive.value = true;

  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const url = `${protocol}//${window.location.host}/api/diagnostics/mtr/stream?target=${encodeURIComponent(mtrTarget.value)}`;

  try {
    mtrWs = new WebSocket(url);
    mtrWs.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        if (Array.isArray(data.hops)) {
          mtrHops.value = data.hops;
        }
      } catch { /* ignore */ }
    };
    mtrWs.onerror = () => {
      mtrError.value = "MTR connection error.";
      mtrActive.value = false;
    };
    mtrWs.onclose = () => {
      mtrActive.value = false;
    };
  } catch {
    mtrActive.value = false;
  }
}

function stopMtr(): void {
  mtrWs?.close();
  mtrWs = null;
  mtrActive.value = false;
}

// --- Automation Scripts ---
async function loadPrebuiltScripts(): Promise<void> {
  try {
    const { data } = await axios.get<{ scripts: PrebuiltScript[] }>("/api/scripts/settings");
    availableScripts.value = data.scripts.filter((s) => s.allowed);
    if (availableScripts.value.length > 0) {
      selectedScript.value = availableScripts.value[0].name;
    }
  } catch {
    // silent fallback
  }
}

async function triggerScript(): Promise<void> {
  if (!selectedScript.value) return;
  let parsedParams = {};
  try {
    parsedParams = JSON.parse(scriptParams.value);
  } catch {
    emit("toast", "error", "Invalid JSON parameters format.");
    return;
  }

  try {
    const { data } = await axios.post<{ job_id: number }>("/api/scripts/prebuilt/run", {
      script_name: selectedScript.value,
      params: parsedParams,
    });
    runningScriptJobId.value = data.job_id;
    scriptJobStatus.value = "running";
    scriptLogs.value = "Initializing job...\n";
    startScriptPolling();
    emit("toast", "success", `Automation script triggered: Job #${data.job_id}`);
  } catch (e: any) {
    emit("toast", "error", e?.response?.data?.detail || "Failed to trigger script");
  }
}

function stopScriptPolling(): void {
  if (scriptPollTimer) {
    window.clearInterval(scriptPollTimer);
    scriptPollTimer = null;
  }
}

function startScriptPolling(): void {
  stopScriptPolling();
  scriptPollTimer = window.setInterval(async () => {
    if (runningScriptJobId.value === null) return;
    try {
      const { data } = await axios.get(`/api/scripts/jobs/${runningScriptJobId.value}`);
      scriptJobStatus.value = data.status;
      scriptLogs.value = data.logs || "";
      if (data.status === "completed" || data.status === "failed") {
        stopScriptPolling();
        emit("toast", "success", `Script job #${runningScriptJobId.value} finished!`);
      }
    } catch {
      // ignore
    }
  }, 2000);
}

// --- Lifecycle ---
async function loadPlaybooks(): Promise<void> {
  playbooksLoading.value = true;
  try {
    const { data } = await axios.get<Playbook[]>("/api/playbooks/");
    playbooks.value = data;
    if (data.length > 0) selectedPlaybookId.value = data[0].id;
  } catch {
    emit("toast", "error", "Failed to load playbooks");
  } finally {
    playbooksLoading.value = false;
  }
}

onMounted(() => {
  loadPlaybooks();
  loadPrebuiltScripts();
});

onBeforeUnmount(() => {
  stopScanPolling();
  stopMtr();
  stopScriptPolling();
});

watch(
  () => currentScanId.value,
  (next) => {
    if (next) startScanPolling();
    else {
      stopScanPolling();
      scanMeta.value = null;
    }
  }
);
</script>

<template>
  <div class="flex flex-col h-full gap-5 relative">
    
    <!-- Header Section -->
    <header class="flex items-end justify-between px-1 shrink-0">
      <div>
        <p class="text-[0.65rem] uppercase tracking-[0.45em] text-white/30">Network Control Posture</p>
        <h1 class="mt-2 text-2xl font-semibold tracking-tight text-white">Operator Toolbox</h1>
      </div>
      <div class="flex items-center gap-2">
        <button
          @click="isTerminalOpen = !isTerminalOpen"
          class="np-cyber-btn flex items-center gap-1.5"
          :class="isTerminalOpen ? 'border-emerald-500/50 text-emerald-400' : ''"
        >
          <span class="w-1.5 h-1.5 rounded-full" :class="currentScanId ? 'bg-emerald-400 animate-pulse' : 'bg-slate-400/25'"></span>
          Console {{ currentScanId ? '(Running)' : '' }}
        </button>
      </div>
    </header>

    <!-- Main Content Panel with Tabs -->
    <div class="flex-1 min-h-0 bg-[var(--np-glass-bg)] border border-slate-600/10 rounded-2xl flex flex-col overflow-hidden backdrop-blur-md">
      
      <!-- Toolbox Tab Switcher -->
      <div class="flex items-center border-b border-slate-600/10 px-4 py-2 gap-1 bg-black/20">
        <button
          v-for="t in ['scanning', 'diagnostics', 'automation']"
          :key="t"
          @click="activeTab = (t as ActiveTab)"
          class="px-4 py-2 text-xs font-semibold tracking-wider uppercase border-b-2 -mb-px transition-colors"
          :class="activeTab === t
            ? 'border-emerald-500 text-emerald-400'
            : 'border-transparent text-slate-400/40 hover:text-emerald-300'"
        >
          {{ t === 'scanning' ? 'Port Scanner' : t === 'diagnostics' ? 'Diagnostic Probes' : 'Automation Scripts' }}
        </button>
      </div>

      <!-- Tab Content Area -->
      <div class="flex-1 p-5 overflow-y-auto custom-scrollbar">
        
        <!-- ======================================= -->
        <!-- TAB 1: PORT SCANNING (NMAP)             -->
        <!-- ======================================= -->
        <div v-if="activeTab === 'scanning'" class="space-y-5">
          <div class="grid grid-cols-1 md:grid-cols-3 gap-5">
            <div class="md:col-span-2">
              <label class="block text-[0.7rem] uppercase tracking-widest text-slate-400/50 mb-1.5">Target Address</label>
              <input
                v-model="target"
                type="text"
                placeholder="192.168.1.1 or 10.0.0.0/24 or example.com"
                class="np-neon-input w-full px-4 py-2.5 text-sm"
              />
            </div>
            <div>
              <label class="block text-[0.7rem] uppercase tracking-widest text-slate-400/50 mb-1.5">Settings</label>
              <div class="flex items-center gap-2 mt-2">
                <input id="save" v-model="saveResults" type="checkbox" class="rounded border-slate-500/20 bg-[#0f0c1e] accent-emerald-500" />
                <label for="save" class="text-xs text-slate-400/60">Log results to database</label>
              </div>
            </div>
          </div>

          <div class="grid grid-cols-1 lg:grid-cols-2 gap-5 pt-3">
            
            <!-- Targeted Presets -->
            <div class="p-4 rounded-xl bg-black/20 border border-slate-600/5 space-y-4">
              <h3 class="text-xs font-bold uppercase tracking-wider text-slate-200">Custom Targeted Scans</h3>
              <div>
                <label class="block text-[0.65rem] uppercase tracking-wider text-slate-400/50 mb-1.5">Scan Presets</label>
                <select v-model="preset" class="np-neon-input w-full px-3 py-2 text-sm bg-transparent outline-none">
                  <option value="ping">Ping Sweep (-sn)</option>
                  <option value="quick">Quick Ports (-F)</option>
                  <option value="services">Services &amp; Scripts (-sV -sC)</option>
                  <option value="full">Full Port Scan (-p-)</option>
                  <option value="vuln">Vulnerability Scan (--script=vuln)</option>
                  <option value="custom">Custom Parameters</option>
                </select>
              </div>

              <div v-if="preset === 'custom'">
                <label class="block text-[0.65rem] uppercase tracking-wider text-slate-400/50 mb-1.5">Custom Nmap Flags</label>
                <input v-model="customCommand" type="text" class="np-neon-input w-full px-3 py-2 text-sm font-mono" />
              </div>

              <div class="flex justify-end pt-2">
                <button
                  @click="runTargeted"
                  :disabled="!isAdmin || !target"
                  class="np-cyber-btn border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10 disabled:opacity-35"
                >
                  Run Targeted Scan
                </button>
              </div>
            </div>

            <!-- Playbooks -->
            <div class="p-4 rounded-xl bg-black/20 border border-slate-600/5 space-y-4">
              <h3 class="text-xs font-bold uppercase tracking-wider text-slate-200">Predefined Security Playbooks</h3>
              <div>
                <label class="block text-[0.65rem] uppercase tracking-wider text-slate-400/50 mb-1.5">Select Playbook</label>
                <select v-model="selectedPlaybookId" class="np-neon-input w-full px-3 py-2 text-sm bg-transparent outline-none" :disabled="playbooksLoading">
                  <option v-for="pb in playbooks" :key="pb.id" :value="pb.id">
                    {{ pb.category }} — {{ pb.name }}
                  </option>
                </select>
              </div>

              <div v-if="selectedPlaybook" class="p-3 rounded bg-white/[0.02] border border-slate-600/10 text-xs">
                <div class="flex items-center justify-between">
                  <span class="font-bold text-slate-200">{{ selectedPlaybook.name }}</span>
                  <span class="font-mono text-emerald-400 uppercase">{{ selectedPlaybook.risk_level }} RISK</span>
                </div>
                <p class="text-slate-400/50 mt-1">{{ selectedPlaybook.description }}</p>
                <p class="font-mono mt-2 text-[10px] text-slate-300/60">Args: {{ selectedPlaybook.nmap_args }}</p>
              </div>

              <div class="flex justify-end pt-2">
                <button
                  @click="runPlaybook"
                  :disabled="!isAdmin || !target || !selectedPlaybook"
                  class="np-cyber-btn border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10 disabled:opacity-35"
                >
                  Run Playbook
                </button>
              </div>
            </div>

          </div>
        </div>

        <!-- ======================================= -->
        <!-- TAB 2: DIAGNOSTIC PROBES                -->
        <!-- ======================================= -->
        <div v-if="activeTab === 'diagnostics'" class="space-y-6">
          <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            
            <!-- TCP Probe -->
            <div class="p-4 rounded-xl bg-black/20 border border-slate-600/5 space-y-4">
              <div>
                <h3 class="text-xs font-bold uppercase tracking-wider text-slate-200">TCP Handshake Probe</h3>
                <p class="text-[0.65rem] text-slate-400/50 mt-1">Measures exact TCP connection response times to verify port accessibility.</p>
              </div>

              <div class="grid grid-cols-3 gap-3">
                <div class="col-span-2">
                  <label class="block text-[0.65rem] uppercase tracking-wider text-slate-400/50 mb-1">Host / IP</label>
                  <input v-model="tcpHost" type="text" placeholder="10.0.0.1" class="np-neon-input w-full px-3 py-2 text-xs" />
                </div>
                <div>
                  <label class="block text-[0.65rem] uppercase tracking-wider text-slate-400/50 mb-1">Port</label>
                  <input v-model.number="tcpPort" type="number" min="1" max="65535" class="np-neon-input w-full px-3 py-2 text-xs" />
                </div>
              </div>

              <div class="flex justify-end">
                <button @click="runTcpTest" :disabled="tcpTesting || !tcpHost" class="np-cyber-btn border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10">
                  {{ tcpTesting ? 'Probing...' : 'Run Probe' }}
                </button>
              </div>

              <div v-if="tcpResult" class="p-3 rounded border text-xs" :class="tcpResult.error ? 'border-red-500/20 bg-red-500/5 text-red-300' : 'border-emerald-500/20 bg-emerald-500/5 text-emerald-300'">
                <p v-if="tcpResult.error">✗ Probe failed: {{ tcpResult.error }}</p>
                <p v-else>✓ TCP Handshake completed in <span class="font-bold font-mono">{{ tcpResult.latency_ms }} ms</span></p>
              </div>
            </div>

            <!-- MTR Traceroute -->
            <div class="p-4 rounded-xl bg-black/20 border border-slate-600/5 space-y-4">
              <div class="flex items-center justify-between">
                <div>
                  <h3 class="text-xs font-bold uppercase tracking-wider text-slate-200">Live MTR Traceroute</h3>
                  <p class="text-[0.65rem] text-slate-400/50 mt-1">Real-time hop latency analysis.</p>
                </div>
                <div class="flex gap-2">
                  <input v-model="mtrTarget" type="text" placeholder="8.8.8.8" class="np-neon-input px-3 py-1.5 text-xs w-36 font-mono" :disabled="mtrActive" />
                  <button v-if="!mtrActive" @click="startMtr" class="np-cyber-btn px-2.5 py-1 text-[10px] border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10">Start</button>
                  <button v-else @click="stopMtr" class="np-cyber-btn px-2.5 py-1 text-[10px] border-red-500/40 text-red-400 hover:bg-red-500/10">Stop</button>
                </div>
              </div>

              <div v-if="mtrError" class="text-xs text-red-400">{{ mtrError }}</div>

              <div class="max-h-56 overflow-y-auto custom-scrollbar border border-slate-600/10 rounded">
                <table class="w-full text-[10px] font-mono text-left">
                  <thead>
                    <tr class="bg-black/45 text-slate-400/60 border-b border-slate-600/10">
                      <th class="px-2 py-1.5">Hop</th>
                      <th class="px-2 py-1.5">Host</th>
                      <th class="px-2 py-1.5 text-right">Loss%</th>
                      <th class="px-2 py-1.5 text-right">Avg ms</th>
                    </tr>
                  </thead>
                  <tbody class="divide-y divide-slate-600/5">
                    <tr v-for="hop in mtrHops" :key="hop.hop" class="hover:bg-white/[0.02]">
                      <td class="px-2 py-1.5 text-slate-400">{{ hop.hop }}</td>
                      <td class="px-2 py-1.5 text-slate-100 truncate max-w-[120px]" :title="hop.host">{{ hop.host }}</td>
                      <td class="px-2 py-1.5 text-right" :class="hop.loss_pct > 0 ? 'text-red-400' : 'text-slate-300/60'">{{ hop.loss_pct }}%</td>
                      <td class="px-2 py-1.5 text-right text-emerald-400 font-bold">{{ hop.avg_ms }}</td>
                    </tr>
                    <tr v-if="mtrHops.length === 0 && !mtrActive">
                      <td colspan="4" class="text-center py-4 text-slate-400/30">Traceroute idle. Press Start.</td>
                    </tr>
                    <tr v-else-if="mtrHops.length === 0 && mtrActive">
                      <td colspan="4" class="text-center py-4 text-emerald-400/50 animate-pulse">Running traceroute sweep...</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

          </div>
        </div>

        <!-- ======================================= -->
        <!-- TAB 3: AUTOMATION SCRIPTS               -->
        <!-- ======================================= -->
        <div v-if="activeTab === 'automation'" class="space-y-4">
          <div class="grid grid-cols-1 lg:grid-cols-3 gap-5">
            
            <!-- Left Side: Controls -->
            <div class="lg:col-span-1 p-4 rounded-xl bg-black/20 border border-slate-600/5 space-y-4">
              <h3 class="text-xs font-bold uppercase tracking-wider text-slate-200">Run Python Automation</h3>
              
              <div>
                <label class="block text-[0.65rem] uppercase tracking-wider text-slate-400/50 mb-1.5">Select Script</label>
                <select v-model="selectedScript" class="np-neon-input w-full px-3 py-2 text-sm bg-transparent outline-none">
                  <option v-for="s in availableScripts" :key="s.name" :value="s.name">{{ s.name }}</option>
                  <option v-if="availableScripts.length === 0" disabled>No scripts allowed</option>
                </select>
              </div>

              <div>
                <label class="block text-[0.65rem] uppercase tracking-wider text-slate-400/50 mb-1.5">JSON Parameters</label>
                <textarea v-model="scriptParams" rows="4" class="np-neon-input w-full p-3 text-xs font-mono"></textarea>
              </div>

              <div class="flex justify-end">
                <button
                  @click="triggerScript"
                  :disabled="!isAdmin || !selectedScript"
                  class="np-cyber-btn border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10 disabled:opacity-35"
                >
                  Run Script Job
                </button>
              </div>
            </div>

            <!-- Right Side: Script Log console -->
            <div class="lg:col-span-2 p-4 rounded-xl bg-black/25 border border-slate-600/10 flex flex-col justify-between min-h-[300px]">
              <div>
                <div class="flex items-center justify-between pb-2 border-b border-slate-600/10 mb-3">
                  <h3 class="text-xs font-bold uppercase tracking-wider text-slate-200">Job Output Console</h3>
                  <span v-if="scriptJobStatus" class="px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase"
                    :class="scriptJobStatus === 'running' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                             scriptJobStatus === 'completed' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                             'bg-red-500/20 text-red-400 border border-red-500/30'"
                  >
                    {{ scriptJobStatus }}
                  </span>
                </div>
                <pre class="text-[10px] font-mono leading-relaxed text-slate-300/80 max-h-60 overflow-y-auto custom-scrollbar whitespace-pre-wrap p-2 rounded bg-black/40 border border-slate-600/5">{{ scriptLogs || 'Select a script and start the job to view log telemetry.' }}</pre>
              </div>
            </div>

          </div>
        </div>

      </div>
    </div>

    <!-- Collapsible Live Terminal Drawer at Bottom -->
    <div 
      class="fixed bottom-0 left-0 right-0 z-50 transition-transform duration-300 bg-[var(--np-glass-bg)] border-t border-slate-600/20 backdrop-blur-lg shadow-2xl flex flex-col"
      :style="{ transform: isTerminalOpen ? 'translateY(0)' : 'translateY(calc(100% - 40px))', height: '280px' }"
    >
      <!-- Drag/Toggle strip -->
      <div 
        @click="isTerminalOpen = !isTerminalOpen" 
        class="h-10 px-6 flex items-center justify-between cursor-pointer border-b border-slate-600/10 select-none bg-black/40"
      >
        <div class="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-200">
          <span class="w-1.5 h-1.5 rounded-full" :class="currentScanId ? 'bg-emerald-400 animate-pulse' : 'bg-slate-400/30'"></span>
          <span>Live Nmap &amp; Diagnostic Console</span>
        </div>
        <button class="text-[10px] font-mono text-slate-400 hover:text-emerald-400">
          {{ isTerminalOpen ? '[ Minimize Console ]' : '[ Expand Console ]' }}
        </button>
      </div>

      <!-- Real-time terminal output component -->
      <div class="flex-1 min-h-0 bg-[var(--np-surface)]">
        <LiveTerminal 
          :title="terminalTitle" 
          :stream-url="terminalStreamUrl" 
          :theme="props.theme" 
        />
      </div>
    </div>

  </div>
</template>

<style scoped>
.custom-scrollbar::-webkit-scrollbar {
  width: 5px;
  height: 5px;
}
.custom-scrollbar::-webkit-scrollbar-track {
  background: rgba(255, 255, 255, 0.01);
}
.custom-scrollbar::-webkit-scrollbar-thumb {
  background: rgba(168, 85, 247, 0.2);
  border-radius: 4px;
}
.custom-scrollbar::-webkit-scrollbar-thumb:hover {
  background: rgba(168, 85, 247, 0.4);
}
</style>
