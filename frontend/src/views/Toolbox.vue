<script setup lang="ts">
import axios from "axios";
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { CircleCheck, CircleX } from "lucide-vue-next";
import LiveTerminal from "../components/features/LiveTerminal.vue";
import { getStoredToken } from "../utils/token";

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

// The last scan is remembered in localStorage so closing the page (or the
// browser) does not lose the run: coming back shows its status and findings
// instead of an empty console.
const LAST_SCAN_KEY = "np:last-scan";

interface ScanPort {
  port: number;
  protocol: string;
  state: string;
  service: string;
  version: string;
}

interface ScanHost {
  address: string;
  hostname: string | null;
  state: string;
  latency_ms: number | null;
  mac_address: string | null;
  vendor: string | null;
  os: string | null;
  open_ports: number;
  ports: ScanPort[];
}

interface ScanSummary {
  exit_code?: number;
  error?: string;
  hosts?: ScanHost[];
  hosts_up?: number;
  hosts_total?: number;
  open_ports?: number;
  scan_seconds?: number | null;
  duration_seconds?: number;
  timeout_seconds?: number;
}

interface ScanMeta {
  id: string;
  command: string;
  target: string;
  scan_type: string;
  started_at: string;
  completed_at: string | null;
  status: string;
  result_summary?: ScanSummary | null;
  ai_briefing?: string | null;
}

const currentScanId = ref<string | null>(null);
const scanMeta = ref<ScanMeta | null>(null);
const scanMetaLoading = ref(false);
const scanHistory = ref<ScanMeta[]>([]);
const historyLoading = ref(false);
const expandedHost = ref<string | null>(null);
let scanPollTimer: number | null = null;

const scanRunning = computed(
  () => !!scanMeta.value && ["pending", "running"].includes(scanMeta.value.status)
);
const scanHosts = computed<ScanHost[]>(() => scanMeta.value?.result_summary?.hosts ?? []);
const scanHostsUp = computed(() => scanMeta.value?.result_summary?.hosts_up ?? scanHosts.value.length);
const scanOpenPorts = computed(
  () =>
    scanMeta.value?.result_summary?.open_ports ??
    scanHosts.value.reduce((total, host) => total + (host.open_ports || 0), 0)
);

function hostTitle(host: ScanHost): string {
  return host.hostname ? `${host.hostname} (${host.address})` : host.address;
}

function statusClass(status: string): string {
  if (status === "completed") return "np-brand-soft np-brand-text border np-brand-border";
  if (status === "failed") return "bg-red-500/15 text-red-400 border border-red-500/30";
  return "np-brand-soft np-brand-text border np-brand-border";
}

function rememberScan(id: string | null): void {
  try {
    if (id) window.localStorage.setItem(LAST_SCAN_KEY, id);
    else window.localStorage.removeItem(LAST_SCAN_KEY);
  } catch {
    // Private-mode browsers have no storage; the page still works this session.
  }
}

// --- Diagnostics State (TCP & MTR) ---
const tcpHost = ref("");
const tcpPort = ref(80);
const tcpTesting = ref(false);
// The probe reports what happened, not just "it failed": open / closed (host
// up, nothing listening) / filtered (host up, packets dropped) / unreachable
// (nothing answers at all).
type TcpVerdict = "open" | "closed" | "filtered" | "unreachable" | "unknown";
const tcpResult = ref<{
  latency_ms: number | null;
  error: string | null;
  verdict?: TcpVerdict;
  hint?: string | null;
  host_reachable?: boolean | null;
} | null>(null);

function tcpVerdictLabel(verdict?: TcpVerdict): string {
  switch (verdict) {
    case "open": return "Open";
    case "closed": return "Closed";
    case "filtered": return "Filtered";
    case "unreachable": return "Host not answering";
    default: return "Inconclusive";
  }
}

function tcpVerdictClass(verdict?: TcpVerdict): string {
  switch (verdict) {
    case "open": return "np-level-info";
    case "closed": return "np-level-info";
    case "filtered": return "np-level-warning";
    case "unreachable": return "np-level-error";
    default: return "np-level-info";
  }
}

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
const terminalToken = computed(() => getStoredToken() || null);
const terminalStreamUrl = computed(() => {
  if (!currentScanId.value || !terminalToken.value) return null;
  // No token in the URL: it rides in the WebSocket subprotocol instead.
  return `${getWsBase()}/api/ws/scans/${currentScanId.value}`;
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

async function loadScanHistory(): Promise<void> {
  historyLoading.value = true;
  try {
    const { data } = await axios.get<ScanMeta[]>("/api/nmap/history");
    scanHistory.value = data;
  } catch {
    scanHistory.value = [];
  } finally {
    historyLoading.value = false;
  }
}

async function fetchScanResult(id: string): Promise<ScanMeta | null> {
  try {
    const { data } = await axios.get<ScanMeta>(`/api/nmap/result/${id}`, {
      params: { include_output: false },
    });
    scanMeta.value = data;
    return data;
  } catch {
    return null;
  }
}

function startScanPolling(): void {
  stopScanPolling();
  scanPollTimer = window.setInterval(async () => {
    const id = currentScanId.value;
    if (!id) return;
    const data = await fetchScanResult(id);
    if (!data) return;
    if (data.status === "completed" || data.status === "failed") {
      stopScanPolling();
      if (data.status === "completed") {
        emit("toast", "success", `Scan finished: ${scanHostsUp.value} host(s) up.`);
      } else {
        emit("toast", "error", `Scan ${id} failed. Output is in the console.`);
      }
      void loadScanHistory();
    }
  }, 2000);
}

async function selectScan(id: string): Promise<void> {
  currentScanId.value = id;
  rememberScan(id);
  await fetchScanResult(id);
  if (scanRunning.value) startScanPolling();
  else isTerminalOpen.value = true;
}

async function restoreLastScan(): Promise<void> {
  let id: string | null = null;
  try {
    id = window.localStorage.getItem(LAST_SCAN_KEY);
  } catch {
    id = null;
  }
  if (!id) return;
  const data = await fetchScanResult(id);
  if (!data) {
    rememberScan(null);
    return;
  }
  currentScanId.value = id;
  if (data.status === "pending" || data.status === "running") startScanPolling();
}

// --- Execute Nmap Scan ---
async function startScan(command: string): Promise<void> {
  if (!props.isAdmin) {
    emit("toast", "warning", "Admin access required to run scans.");
    return;
  }
  if (!target.value.trim()) {
    emit("toast", "warning", "Enter a target IP or hostname.");
    return;
  }

  try {
    const { data } = await axios.post<{ id: string }>("/api/nmap/execute", {
      command,
      target: target.value.trim(),
      save_results: saveResults.value,
    });
    currentScanId.value = data.id;
    rememberScan(data.id);
    scanMeta.value = null;
    isTerminalOpen.value = true;
    startScanPolling();
    void loadScanHistory();
    emit("toast", "success", `Scan queued: ${data.id}`);
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
    const { data } = await axios.post<{
      latency_ms: number | null;
      error: string | null;
      verdict?: TcpVerdict;
      hint?: string | null;
      host_reachable?: boolean | null;
    }>("/api/insights/tcp-probe", { host, port: tcpPort.value, timeout_s: 5 });
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
    scriptLogs.value = "Initializing job…\n";
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
  void loadScanHistory();
  void restoreLastScan();
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
      rememberScan(null);
    }
  }
);
</script>

<template>
  <div class="flex flex-col h-full gap-5 relative">
    
    <!-- Header Section -->
    <header class="flex items-end justify-between px-1 shrink-0">
      <div>
        <h1 class="text-2xl font-extrabold tracking-tight text-[var(--np-text)]">Toolbox</h1>
        <p class="mt-1 text-xs text-[var(--np-text-muted)]">Scans, probes and automation jobs against the devices in your inventory.</p>
      </div>
      <div class="flex items-center gap-2">
        <button
          @click="isTerminalOpen = !isTerminalOpen"
          class="np-cyber-btn flex items-center gap-1.5"
          :class="isTerminalOpen ? 'np-brand-border np-brand-text' : ''"
        >
          <span class="w-1.5 h-1.5 rounded-full" :class="currentScanId ? 'np-brand-bg animate-pulse' : 'bg-[var(--np-text-dim)]/30'"></span>
          Console {{ currentScanId ? '(running)' : '' }}
        </button>
      </div>
    </header>

    <!-- Main Content Panel with Tabs -->
    <div class="flex-1 min-h-0 bg-[var(--np-glass-bg)] border border-[var(--np-border-subtle)] rounded-2xl flex flex-col overflow-hidden backdrop-blur-md">
      
      <!-- Toolbox Tab Switcher -->
      <div class="flex items-center border-b border-[var(--np-border-subtle)] px-4 py-2 gap-1 bg-[var(--np-thead-bg)]">
        <button
          v-for="t in ['scanning', 'diagnostics', 'automation']"
          :key="t"
          @click="activeTab = (t as ActiveTab)"
          class="px-4 py-2 text-xs uppercase tracking-wider transition-colors np-subtab-btn"
          :class="{ 'active': activeTab === t }"
        >
          {{ t === 'scanning' ? 'Port scanner' : t === 'diagnostics' ? 'Diagnostics' : 'Automation' }}
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
              <label class="block text-[0.7rem] uppercase tracking-widest text-[var(--np-text-dim)]/50 mb-1.5">Target Address</label>
              <input
                v-model="target"
                type="text"
                placeholder="192.168.1.1 or 10.0.0.0/24 or example.com"
                class="np-neon-input w-full px-4 py-2.5 text-sm"
              />
            </div>
            <div>
              <label class="block text-[0.7rem] uppercase tracking-widest text-[var(--np-text-dim)]/50 mb-1.5">Settings</label>
              <div class="flex items-center gap-2 mt-2">
                <input id="save" v-model="saveResults" type="checkbox" class="rounded accent-[var(--np-accent)]" style="border-color: var(--np-border); background: var(--np-surface)" />
                <label for="save" class="text-xs text-[var(--np-text-dim)]/60">Log results to database</label>
              </div>
            </div>
          </div>

          <!-- Results. The console is only useful while a scan runs; these two
               panels are what you come back to when it has finished. -->
          <div v-if="scanMeta || scanHistory.length" class="grid grid-cols-1 lg:grid-cols-3 gap-5">
            <div class="lg:col-span-2 p-4 rounded-xl bg-[var(--np-thead-bg)] border border-[var(--np-border-subtle)] space-y-3">
              <div class="flex items-start justify-between gap-3">
                <div>
                  <h3 class="text-xs font-bold uppercase tracking-wider text-[var(--np-text)]">Last scan findings</h3>
                  <p v-if="scanMeta" class="mt-1 font-mono text-[0.65rem] text-[var(--np-text-dim)]/70">
                    {{ scanMeta.target }} · {{ scanMeta.scan_type }}
                  </p>
                  <p v-else class="mt-1 text-[0.65rem] text-[var(--np-text-dim)]/60">
                    No scan loaded. Pick one from the list on the right.
                  </p>
                </div>
                <span v-if="scanMeta" class="px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase" :class="statusClass(scanMeta.status)">
                  {{ scanMeta.status }}
                </span>
              </div>

              <div v-if="scanMeta" class="flex flex-wrap gap-2 text-[0.6rem] font-mono uppercase tracking-wider">
                <span class="rounded border border-[var(--np-border-subtle)] px-2 py-1 text-[var(--np-text)]">
                  {{ scanHostsUp }} host(s) up
                </span>
                <span class="rounded border border-[var(--np-border-subtle)] px-2 py-1 text-[var(--np-text)]">
                  {{ scanOpenPorts }} open port(s)
                </span>
                <span v-if="scanMeta.result_summary?.scan_seconds" class="rounded border border-[var(--np-border-subtle)] px-2 py-1 text-[var(--np-text-dim)]">
                  {{ scanMeta.result_summary.scan_seconds }}s in nmap
                </span>
                <span v-if="scanMeta.result_summary?.error" class="rounded border border-red-500/40 px-2 py-1 text-red-400">
                  {{ scanMeta.result_summary.error }}
                </span>
              </div>

              <p v-if="scanMeta && scanRunning" class="text-[0.65rem] text-[var(--np-text-dim)]/70 animate-pulse">
                Running — findings appear here as soon as nmap finishes.
              </p>

              <div v-else-if="scanMeta && scanHosts.length === 0" class="text-[0.65rem] text-[var(--np-text-dim)]/70">
                No hosts answered. That is a finding too: nothing on this target responded to the probe.
              </div>

              <div v-else-if="scanHosts.length" class="overflow-x-auto custom-scrollbar">
                <table class="w-full text-[0.65rem] font-mono text-left">
                  <thead>
                    <tr class="text-[0.55rem] uppercase tracking-wider text-[var(--np-text-dim)]/60 border-b border-[var(--np-border-subtle)]">
                      <th class="py-1.5 pr-2">Host</th>
                      <th class="py-1.5 pr-2">Name</th>
                      <th class="py-1.5 pr-2 text-right">Latency</th>
                      <th class="py-1.5 pr-2 text-right">Open</th>
                    </tr>
                  </thead>
                  <tbody class="divide-y divide-[var(--np-border-subtle)]">
                    <template v-for="host in scanHosts" :key="host.address">
                      <tr
                        class="cursor-pointer hover:bg-[var(--np-surface-elevated)]"
                        @click="expandedHost = expandedHost === host.address ? null : host.address"
                      >
                        <td class="py-1.5 pr-2 text-[var(--np-text)]">{{ host.address }}</td>
                        <td class="py-1.5 pr-2 text-[var(--np-text-muted)] truncate max-w-[140px]" :title="hostTitle(host)">
                          {{ host.hostname || host.vendor || '—' }}
                        </td>
                        <td class="py-1.5 pr-2 text-right text-[var(--np-text-dim)]">
                          {{ host.latency_ms !== null ? host.latency_ms + ' ms' : '—' }}
                        </td>
                        <td class="py-1.5 pr-2 text-right np-brand-text font-bold">{{ host.open_ports }}</td>
                      </tr>
                      <tr v-if="expandedHost === host.address">
                        <td colspan="4" class="pb-2">
                          <p v-if="host.ports.length === 0" class="text-[0.6rem] text-[var(--np-text-dim)]/60">
                            No port detail (ping sweep).
                          </p>
                          <ul v-else class="space-y-0.5">
                            <li v-for="p in host.ports" :key="p.port + p.protocol" class="flex gap-2 text-[0.6rem]">
                              <span class="w-14 shrink-0 text-[var(--np-text)]">{{ p.port }}/{{ p.protocol }}</span>
                              <span class="w-14 shrink-0" :class="p.state === 'open' ? 'np-brand-text' : 'text-[var(--np-text-dim)]/60'">{{ p.state }}</span>
                              <span class="text-[var(--np-text-muted)]">{{ p.service }}</span>
                              <span class="truncate text-[var(--np-text-dim)]/60" :title="p.version">{{ p.version }}</span>
                            </li>
                          </ul>
                        </td>
                      </tr>
                    </template>
                  </tbody>
                </table>
              </div>
            </div>

            <div class="lg:col-span-1 p-4 rounded-xl bg-[var(--np-thead-bg)] border border-[var(--np-border-subtle)] space-y-3">
              <div class="flex items-center justify-between">
                <h3 class="text-xs font-bold uppercase tracking-wider text-[var(--np-text)]">Recent scans</h3>
                <button class="text-[10px] font-mono text-[var(--np-text-dim)] hover:np-brand-text" @click="loadScanHistory">
                  {{ historyLoading ? '…' : 'Refresh' }}
                </button>
              </div>
              <p v-if="scanHistory.length === 0" class="text-[0.65rem] text-[var(--np-text-dim)]/60">
                No scans yet.
              </p>
              <ul v-else class="max-h-64 overflow-y-auto custom-scrollbar space-y-1">
                <li v-for="job in scanHistory" :key="job.id">
                  <button
                    class="w-full rounded border px-2 py-1.5 text-left transition-colors"
                    :class="job.id === currentScanId ? 'np-brand-border np-brand-soft' : 'border-[var(--np-border-subtle)] hover:bg-[var(--np-surface-elevated)]'"
                    @click="selectScan(job.id)"
                  >
                    <div class="flex items-center justify-between gap-2">
                      <span class="truncate font-mono text-[0.65rem] text-[var(--np-text)]">{{ job.target }}</span>
                      <span class="shrink-0 text-[9px] font-mono uppercase" :class="job.status === 'failed' ? 'text-red-400' : job.status === 'completed' ? 'np-brand-text' : 'text-[var(--np-text-dim)]'">
                        {{ job.status }}
                      </span>
                    </div>
                    <div class="text-[0.55rem] font-mono uppercase tracking-wider text-[var(--np-text-dim)]/60">
                      {{ job.scan_type }} · {{ job.result_summary?.hosts_up ?? 0 }} up ·
                      {{ job.result_summary?.open_ports ?? 0 }} ports
                    </div>
                  </button>
                </li>
              </ul>
            </div>
          </div>

          <div class="grid grid-cols-1 lg:grid-cols-2 gap-5 pt-3">
            
            <!-- Targeted Presets -->
            <div class="p-4 rounded-xl bg-[var(--np-thead-bg)] border border-[var(--np-border-subtle)] space-y-4">
              <h3 class="text-xs font-bold uppercase tracking-wider text-[var(--np-text)]">Targeted scans</h3>
              <div>
                <label class="block text-[0.65rem] uppercase tracking-wider text-[var(--np-text-dim)]/50 mb-1.5">Preset</label>
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
                <label class="block text-[0.65rem] uppercase tracking-wider text-[var(--np-text-dim)]/50 mb-1.5">Custom Nmap Flags</label>
                <input v-model="customCommand" type="text" class="np-neon-input w-full px-3 py-2 text-sm font-mono" />
              </div>

              <div class="flex justify-end pt-2">
                <button
                  @click="runTargeted"
                  :disabled="!isAdmin || !target"
                  class="np-cyber-btn np-cyber-btn--solid disabled:opacity-50"
                >
                  Run targeted scan
                </button>
              </div>
            </div>

            <!-- Playbooks -->
            <div class="p-4 rounded-xl bg-[var(--np-thead-bg)] border border-[var(--np-border-subtle)] space-y-4">
              <h3 class="text-xs font-bold uppercase tracking-wider text-[var(--np-text)]">Playbooks</h3>
              <div>
                <label class="block text-[0.65rem] uppercase tracking-wider text-[var(--np-text-dim)]/50 mb-1.5">Playbook</label>
                <select v-model="selectedPlaybookId" class="np-neon-input w-full px-3 py-2 text-sm bg-transparent outline-none" :disabled="playbooksLoading">
                  <option v-for="pb in playbooks" :key="pb.id" :value="pb.id">
                    {{ pb.category }} — {{ pb.name }}
                  </option>
                </select>
              </div>

              <div v-if="selectedPlaybook" class="p-3 rounded bg-[var(--np-surface-elevated)] border border-[var(--np-border-subtle)] text-xs">
                <div class="flex items-center justify-between">
                  <span class="font-bold text-[var(--np-text)]">{{ selectedPlaybook.name }}</span>
                  <span class="font-mono np-brand-text uppercase">{{ selectedPlaybook.risk_level }} RISK</span>
                </div>
                <p class="text-[var(--np-text-dim)]/50 mt-1">{{ selectedPlaybook.description }}</p>
                <p class="font-mono mt-2 text-[10px] text-[var(--np-text-muted)]/60">Args: {{ selectedPlaybook.nmap_args }}</p>
              </div>

              <div class="flex justify-end pt-2">
                <button
                  @click="runPlaybook"
                  :disabled="!isAdmin || !target || !selectedPlaybook"
                  class="np-cyber-btn np-cyber-btn--solid disabled:opacity-50"
                >
                  Run playbook
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
            <div class="p-4 rounded-xl bg-[var(--np-thead-bg)] border border-[var(--np-border-subtle)] space-y-4">
              <div>
                <h3 class="text-xs font-bold uppercase tracking-wider text-[var(--np-text)]">TCP Handshake Probe</h3>
                <p class="text-[0.65rem] text-[var(--np-text-dim)]/50 mt-1">Measures exact TCP connection response times to verify port accessibility.</p>
              </div>

              <div class="grid grid-cols-3 gap-3">
                <div class="col-span-2">
                  <label class="block text-[0.65rem] uppercase tracking-wider text-[var(--np-text-dim)]/50 mb-1">Host / IP</label>
                  <input v-model="tcpHost" type="text" placeholder="10.0.0.1" class="np-neon-input w-full px-3 py-2 text-xs" />
                </div>
                <div>
                  <label class="block text-[0.65rem] uppercase tracking-wider text-[var(--np-text-dim)]/50 mb-1">Port</label>
                  <input v-model.number="tcpPort" type="number" min="1" max="65535" class="np-neon-input w-full px-3 py-2 text-xs" />
                </div>
              </div>

              <div class="flex justify-end">
                <button @click="runTcpTest" :disabled="tcpTesting || !tcpHost" class="np-cyber-btn np-cyber-btn--solid">
                  {{ tcpTesting ? 'Probing…' : 'Run probe' }}
                </button>
              </div>

              <div v-if="tcpResult" class="p-3 rounded text-xs space-y-1" :class="tcpVerdictClass(tcpResult.verdict)">
                <p class="flex items-center gap-1.5 font-bold uppercase tracking-wide text-[0.6rem]">
                  <CircleCheck v-if="tcpResult.verdict === 'open'" class="h-3.5 w-3.5 shrink-0" :stroke-width="1.7" />
                  <CircleX v-else class="h-3.5 w-3.5 shrink-0" :stroke-width="1.7" />
                  {{ tcpVerdictLabel(tcpResult.verdict) }}
                  <span v-if="tcpResult.latency_ms !== null" class="font-mono normal-case font-normal">
                    · {{ tcpResult.latency_ms }} ms handshake
                  </span>
                </p>
                <p v-if="tcpResult.error" class="font-mono text-[0.65rem]">{{ tcpResult.error }}</p>
                <p v-if="tcpResult.hint" class="text-[0.65rem] opacity-90">{{ tcpResult.hint }}</p>
              </div>
            </div>

            <!-- MTR Traceroute -->
            <div class="p-4 rounded-xl bg-[var(--np-thead-bg)] border border-[var(--np-border-subtle)] space-y-4">
              <div class="flex items-center justify-between">
                <div>
                  <h3 class="text-xs font-bold uppercase tracking-wider text-[var(--np-text)]">Live MTR Traceroute</h3>
                  <p class="text-[0.65rem] text-[var(--np-text-dim)]/50 mt-1">Real-time hop latency analysis.</p>
                </div>
                <div class="flex gap-2">
                  <input v-model="mtrTarget" type="text" placeholder="8.8.8.8" class="np-neon-input px-3 py-1.5 text-xs w-36 font-mono" :disabled="mtrActive" />
                  <button v-if="!mtrActive" @click="startMtr" class="np-cyber-btn px-2.5 py-1 text-[10px] np-brand-border np-brand-text hover:np-brand-soft">Start</button>
                  <button v-else @click="stopMtr" class="np-cyber-btn px-2.5 py-1 text-[10px] border-red-500/40 text-red-400 hover:bg-red-500/10">Stop</button>
                </div>
              </div>

              <div v-if="mtrError" class="text-xs text-red-400">{{ mtrError }}</div>

              <div class="max-h-56 overflow-y-auto custom-scrollbar border border-[var(--np-border-subtle)] rounded">
                <table class="w-full text-[10px] font-mono text-left">
                  <thead>
                    <tr class="bg-[var(--np-thead-bg)] text-[var(--np-text-dim)] border-b border-[var(--np-border-subtle)]">
                      <th class="px-2 py-1.5">Hop</th>
                      <th class="px-2 py-1.5">Host</th>
                      <th class="px-2 py-1.5 text-right">Loss%</th>
                      <th class="px-2 py-1.5 text-right">Avg ms</th>
                    </tr>
                  </thead>
                  <tbody class="divide-y divide-[var(--np-border-subtle)]">
                    <tr v-for="hop in mtrHops" :key="hop.hop" class="hover:bg-[var(--np-surface-elevated)]">
                      <td class="px-2 py-1.5 text-[var(--np-text-dim)]">{{ hop.hop }}</td>
                      <td class="px-2 py-1.5 text-[var(--np-text)] truncate max-w-[120px]" :title="hop.host">{{ hop.host }}</td>
                      <td class="px-2 py-1.5 text-right" :class="hop.loss_pct > 0 ? 'text-red-400' : 'text-[var(--np-text-muted)]/60'">{{ hop.loss_pct }}%</td>
                      <td class="px-2 py-1.5 text-right np-brand-text font-bold">{{ hop.avg_ms }}</td>
                    </tr>
                    <tr v-if="mtrHops.length === 0 && !mtrActive">
                      <td colspan="4" class="text-center py-4 text-[var(--np-text-dim)]/30">Traceroute idle. Press Start.</td>
                    </tr>
                    <tr v-else-if="mtrHops.length === 0 && mtrActive">
                      <td colspan="4" class="text-center py-4 np-brand-text/50 animate-pulse">Running traceroute sweep…</td>
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
            <div class="lg:col-span-1 p-4 rounded-xl bg-[var(--np-thead-bg)] border border-[var(--np-border-subtle)] space-y-4">
              <h3 class="text-xs font-bold uppercase tracking-wider text-[var(--np-text)]">Automation scripts</h3>
              
              <div>
                <label class="block text-[0.65rem] uppercase tracking-wider text-[var(--np-text-dim)]/50 mb-1.5">Script</label>
                <select v-model="selectedScript" class="np-neon-input w-full px-3 py-2 text-sm bg-transparent outline-none">
                  <option v-for="s in availableScripts" :key="s.name" :value="s.name">{{ s.name }}</option>
                  <option v-if="availableScripts.length === 0" disabled>No scripts allowed</option>
                </select>
              </div>

              <div>
                <label class="block text-[0.65rem] uppercase tracking-wider text-[var(--np-text-dim)]/50 mb-1.5">Parameters (JSON)</label>
                <textarea
                  v-model="scriptParams"
                  rows="4"
                  class="np-neon-input w-full p-3 text-xs font-mono"
                  placeholder='{ "target": "192.168.1.10" }'
                  spellcheck="false"
                ></textarea>
                <p class="mt-1 text-[0.6rem] text-[var(--np-text-dim)]/70">
                  Optional JSON arguments, for example {"target": "192.168.1.10"}.
                </p>
              </div>

              <div class="flex justify-end">
                <button
                  @click="triggerScript"
                  :disabled="!isAdmin || !selectedScript"
                  class="np-cyber-btn np-cyber-btn--solid disabled:opacity-50"
                >
                  Run script job
                </button>
              </div>
            </div>

            <!-- Right Side: Script Log console -->
            <div class="lg:col-span-2 p-4 rounded-xl bg-[var(--np-surface-elevated)] border border-[var(--np-border-subtle)] flex flex-col justify-between min-h-[300px]">
              <div>
                <div class="flex items-center justify-between pb-2 border-b border-[var(--np-border-subtle)] mb-3">
                  <h3 class="text-xs font-bold uppercase tracking-wider text-[var(--np-text)]">Job Output Console</h3>
                  <span v-if="scriptJobStatus" class="px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase"
                    :class="scriptJobStatus === 'running' ? 'np-brand-soft np-brand-text border np-brand-border' :
                             scriptJobStatus === 'completed' ? 'np-brand-soft np-brand-text border np-brand-border' :
                             'bg-red-500/20 text-red-400 border border-red-500/30'"
                  >
                    {{ scriptJobStatus }}
                  </span>
                </div>
                <pre class="text-[10px] font-mono leading-relaxed text-[var(--np-text-muted)] max-h-60 overflow-y-auto custom-scrollbar whitespace-pre-wrap p-2 rounded bg-[var(--np-surface-elevated)] border border-[var(--np-border-subtle)]">{{ scriptLogs || 'Select a script and start a job to see its output.' }}</pre>
              </div>
            </div>

          </div>
        </div>

      </div>
    </div>

    <!-- Collapsible Live Terminal Drawer at Bottom -->
    <div 
      class="fixed bottom-0 left-0 right-0 z-50 transition-transform duration-300 bg-[var(--np-glass-bg)] border-t border-[var(--np-border)] backdrop-blur-lg shadow-2xl flex flex-col"
      :style="{ transform: isTerminalOpen ? 'translateY(0)' : 'translateY(calc(100% - 40px))', height: '280px' }"
    >
      <!-- Drag/Toggle strip -->
      <div 
        @click="isTerminalOpen = !isTerminalOpen" 
        class="h-10 px-6 flex items-center justify-between cursor-pointer border-b border-[var(--np-border-subtle)] select-none bg-[var(--np-surface-elevated)]"
      >
        <div class="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-[var(--np-text)]">
          <span class="w-1.5 h-1.5 rounded-full" :class="currentScanId ? 'np-brand-bg animate-pulse' : 'bg-[var(--np-text-dim)]/30'"></span>
          <span>Live Nmap &amp; Diagnostic Console</span>
        </div>
        <button class="text-[10px] font-mono text-[var(--np-text-dim)] hover:np-brand-text">
          {{ isTerminalOpen ? '[ Minimize Console ]' : '[ Expand Console ]' }}
        </button>
      </div>

      <!-- Real-time terminal output component -->
      <div class="flex-1 min-h-0 bg-[var(--np-surface)]">
        <LiveTerminal
          :title="terminalTitle"
          :stream-url="terminalStreamUrl"
          :theme="props.theme"
          :token="terminalToken"
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
