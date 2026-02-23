<script setup lang="ts">
import axios from "axios";
import { computed, onMounted, ref } from "vue";

type Theme = "nightshade" | "sysadmin";

interface Props {
  theme: Theme;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  (e: "toast", type: "success" | "error" | "warning" | "info", message: string): void;
}>();

const isNightshade = computed(() => props.theme === "nightshade");

const activeTab = ref<"presets" | "nse" | "custom" | "nettools" | "history">("presets");
const tabs = [
  { id: "presets" as const, label: "Presets" },
  { id: "nse" as const, label: "NSE Scripts" },
  { id: "custom" as const, label: "Custom" },
  { id: "nettools" as const, label: "Network Tools" },
  { id: "history" as const, label: "History" },
];

const activeNetTool = ref<"traceroute" | "ping" | "dns" | "whois" | "capture">("traceroute");
const netTools = [
  { id: "traceroute" as const, label: "Traceroute" },
  { id: "ping" as const, label: "Ping Sweep" },
  { id: "dns" as const, label: "DNS Lookup" },
  { id: "whois" as const, label: "Whois" },
  { id: "capture" as const, label: "Packet Capture" },
];

interface Preset {
  id: string;
  name: string;
  command: string;
  description: string;
}

interface ScanResult {
  id: string;
  command: string;
  target: string;
  scan_type: string;
  started_at: string;
  completed_at: string | null;
  status: string;
  output: string | null;
  file_path: string | null;
}

interface NseScript {
  name: string;
  command: string;
  description: string;
  category: string;
}

interface TracerouteHop {
  hop: number;
  ip: string | null;
  rtt_ms: number[] | null;
  is_timeout: boolean;
}

const target = ref("");
const command = ref("nmap -sV -T3");
const aiDescription = ref("");
const saveResults = ref(true);

const currentScan = ref<ScanResult | null>(null);
const scanHistory = ref<ScanResult[]>([]);
const presets = ref<Preset[]>([]);

const loading = ref(false);
const aiLoading = ref(false);
const error = ref<string | null>(null);
const aiExplanation = ref<string | null>(null);
const pollInterval = ref<number | null>(null);

const nseCategory = ref("all");
const nseScripts: NseScript[] = [
  { name: "banner", command: "nmap -sV --script=banner", description: "Banner grabbing", category: "Discovery" },
  { name: "dns-brute", command: "nmap --script=dns-brute", description: "DNS subdomain brute force", category: "Discovery" },
  { name: "http-title", command: "nmap -p 80,443 --script=http-title", description: "HTTP page titles", category: "Discovery" },
  { name: "snmp-info", command: "nmap -sU -p 161 --script=snmp-info", description: "SNMP device info", category: "Discovery" },
  { name: "vuln", command: "nmap -sV --script=vuln", description: "All vulnerability scripts", category: "Vulnerability" },
  { name: "http-sql-injection", command: "nmap -p 80,443 --script=http-sql-injection", description: "SQL injection check", category: "Vulnerability" },
  { name: "smb-vuln-ms17-010", command: "nmap -p 445 --script=smb-vuln-ms17-010", description: "EternalBlue check", category: "Vulnerability" },
  { name: "ssl-heartbleed", command: "nmap -p 443 --script=ssl-heartbleed", description: "Heartbleed check", category: "Vulnerability" },
  { name: "ftp-anon", command: "nmap -p 21 --script=ftp-anon", description: "Anonymous FTP check", category: "Authentication" },
  { name: "mysql-empty-password", command: "nmap -p 3306 --script=mysql-empty-password", description: "MySQL no-password check", category: "Authentication" },
  { name: "ssh-auth-methods", command: "nmap -p 22 --script=ssh-auth-methods", description: "SSH auth methods", category: "Authentication" },
  { name: "http-brute", command: "nmap -p 80,443 --script=http-brute", description: "HTTP brute force", category: "Brute Force" },
  { name: "ssh-brute", command: "nmap -p 22 --script=ssh-brute", description: "SSH brute force", category: "Brute Force" },
  { name: "ftp-brute", command: "nmap -p 21 --script=ftp-brute", description: "FTP brute force", category: "Brute Force" },
  { name: "ssl-cert", command: "nmap -p 443 --script=ssl-cert", description: "SSL certificate info", category: "SSL/TLS" },
  { name: "ssl-enum-ciphers", command: "nmap -p 443 --script=ssl-enum-ciphers", description: "SSL cipher enumeration", category: "SSL/TLS" },
  { name: "tls-ticketbleed", command: "nmap -p 443 --script=tls-ticketbleed", description: "TLS Ticketbleed check", category: "SSL/TLS" },
];

const nseCategories = ["all", "Discovery", "Vulnerability", "Authentication", "Brute Force", "SSL/TLS"];

const filteredNseScripts = computed(() => {
  if (nseCategory.value === "all") return nseScripts;
  return nseScripts.filter((s) => s.category === nseCategory.value);
});

function selectNseScript(script: NseScript): void {
  command.value = script.command;
  activeTab.value = "custom";
}

const tracerouteTarget = ref("");
const tracerouteLoading = ref(false);
const tracerouteError = ref<string | null>(null);
const tracerouteHops = ref<TracerouteHop[]>([]);
const tracerouteRawOutput = ref("");
const tracerouteShowRaw = ref(false);

const pingSweepTarget = ref("");
const pingSweepLoading = ref(false);
const pingSweepError = ref<string | null>(null);
const pingSweepResults = ref<{ ip: string; status: string; latency?: string }[]>([]);

const dnsTarget = ref("");
const dnsLoading = ref(false);
const dnsError = ref<string | null>(null);
const dnsResults = ref<Record<string, string[]> | null>(null);

const whoisTarget = ref("");
const whoisLoading = ref(false);
const whoisError = ref<string | null>(null);
const whoisResult = ref<string>("");

const captureInterface = ref("any");
const captureFilter = ref("");
const captureDuration = ref(10);
const captureCount = ref(100);
const captureLoading = ref(false);
const captureError = ref<string | null>(null);
const capturePackets = ref<{ timestamp: string; source: string; destination: string; protocol: string; length: string; info: string }[]>([]);
const captureRawOutput = ref("");
const captureShowRaw = ref(false);

async function runTraceroute(): Promise<void> {
  if (!tracerouteTarget.value.trim()) {
    tracerouteError.value = "Enter a target IP or hostname";
    return;
  }
  tracerouteLoading.value = true;
  tracerouteError.value = null;
  tracerouteHops.value = [];
  tracerouteRawOutput.value = "";
  tracerouteShowRaw.value = false;
  try {
    const { data } = await axios.post<{ target: string; hops: TracerouteHop[]; raw_output: string }>("/api/nmap/traceroute", {
      target: tracerouteTarget.value,
    });
    tracerouteHops.value = data.hops;
    tracerouteRawOutput.value = data.raw_output;
    emit("toast", "success", `Traceroute to ${data.target} completed`);
  } catch (e: any) {
    tracerouteError.value = e.response?.data?.detail || "Failed to run traceroute";
  } finally {
    tracerouteLoading.value = false;
  }
}

async function runPingSweep(): Promise<void> {
  if (!pingSweepTarget.value.trim()) {
    pingSweepError.value = "Enter a target subnet";
    return;
  }
  pingSweepLoading.value = true;
  pingSweepError.value = null;
  pingSweepResults.value = [];
  try {
    const { data } = await axios.post<{ hosts: { ip: string; status: string; latency?: string }[] }>("/api/nmap/ping-sweep", {
      target: pingSweepTarget.value,
    });
    pingSweepResults.value = data.hosts;
    emit("toast", "success", `Ping sweep completed: ${data.hosts.length} hosts found`);
  } catch (e: any) {
    pingSweepError.value = e.response?.data?.detail || "Failed to run ping sweep";
  } finally {
    pingSweepLoading.value = false;
  }
}

async function runDnsLookup(): Promise<void> {
  if (!dnsTarget.value.trim()) {
    dnsError.value = "Enter a hostname";
    return;
  }
  dnsLoading.value = true;
  dnsError.value = null;
  dnsResults.value = null;
  try {
    const { data } = await axios.post<{ records: Record<string, string[]> }>("/api/nmap/dns-lookup", {
      target: dnsTarget.value,
    });
    dnsResults.value = data.records;
    emit("toast", "success", `DNS lookup for ${dnsTarget.value} completed`);
  } catch (e: any) {
    dnsError.value = e.response?.data?.detail || "Failed to run DNS lookup";
  } finally {
    dnsLoading.value = false;
  }
}

async function runWhois(): Promise<void> {
  if (!whoisTarget.value.trim()) {
    whoisError.value = "Enter an IP or domain";
    return;
  }
  whoisLoading.value = true;
  whoisError.value = null;
  whoisResult.value = "";
  try {
    const { data } = await axios.post<{ result: string }>("/api/nmap/whois", {
      target: whoisTarget.value,
    });
    whoisResult.value = data.result;
    emit("toast", "success", `Whois lookup for ${whoisTarget.value} completed`);
  } catch (e: any) {
    whoisError.value = e.response?.data?.detail || "Failed to run whois lookup";
  } finally {
    whoisLoading.value = false;
  }
}

async function runCapture(): Promise<void> {
  captureLoading.value = true;
  captureError.value = null;
  capturePackets.value = [];
  captureRawOutput.value = "";
  captureShowRaw.value = false;
  try {
    const { data } = await axios.post<{ packets: { timestamp: string; source: string; destination: string; protocol: string; length: string; info: string }[]; raw_output: string }>("/api/nmap/capture", {
      interface: captureInterface.value,
      filter: captureFilter.value,
      duration: captureDuration.value,
      count: captureCount.value,
    });
    capturePackets.value = data.packets;
    captureRawOutput.value = data.raw_output;
    emit("toast", "success", `Captured ${data.packets.length} packets`);
  } catch (e: any) {
    captureError.value = e.response?.data?.detail || "Failed to run packet capture";
  } finally {
    captureLoading.value = false;
  }
}

function rttColor(rtt: number): string {
  const isNightshade = document.body.classList.contains("theme-nightshade");
  if (rtt < 30) return isNightshade ? "text-emerald-400" : "text-green-500";
  if (rtt <= 100) return "text-amber-400";
  return "text-rose-400";
}

function avgRtt(rtts: number[]): number {
  return rtts.reduce((a, b) => a + b, 0) / rtts.length;
}

async function loadPresets(): Promise<void> {
  try {
    const { data } = await axios.get<Preset[]>("/api/nmap/presets");
    presets.value = data;
  } catch {}
}

async function loadHistory(): Promise<void> {
  try {
    const { data } = await axios.get<ScanResult[]>("/api/nmap/history");
    scanHistory.value = data;
  } catch {}
}

function selectPreset(preset: Preset): void {
  command.value = preset.command;
  activeTab.value = "custom";
}

async function generateAICommand(): Promise<void> {
  if (!aiDescription.value.trim() || !target.value.trim()) {
    error.value = "Enter a description and target IP";
    return;
  }
  aiLoading.value = true;
  error.value = null;
  aiExplanation.value = null;
  try {
    const { data } = await axios.post<{ command: string; explanation: string }>("/api/nmap/ai-command", {
      description: aiDescription.value,
      target: target.value,
    });
    command.value = data.command;
    aiExplanation.value = data.explanation;
  } catch {
    error.value = "Failed to generate command";
  } finally {
    aiLoading.value = false;
  }
}

async function executeScan(): Promise<void> {
  if (!target.value.trim()) {
    error.value = "Enter a target IP or hostname";
    return;
  }
  loading.value = true;
  error.value = null;
  currentScan.value = null;
  try {
    const { data } = await axios.post<ScanResult>("/api/nmap/execute", {
      command: command.value,
      target: target.value,
      save_results: saveResults.value,
    });
    currentScan.value = data;
    pollInterval.value = window.setInterval(async () => {
      try {
        const { data: result } = await axios.get<ScanResult>(`/api/nmap/result/${data.id}`);
        currentScan.value = result;
        if (result.status === "completed" || result.status === "error" || result.status === "timeout") {
          if (pollInterval.value) {
            clearInterval(pollInterval.value);
            pollInterval.value = null;
          }
          loading.value = false;
          await loadHistory();
          if (result.status === "completed") emit("toast", "success", `Scan completed: ${result.scan_type} on ${result.target}`);
          else if (result.status === "error") emit("toast", "error", `Scan failed: ${result.target}`);
          else if (result.status === "timeout") emit("toast", "warning", `Scan timed out: ${result.target}`);
        }
      } catch {}
    }, 2000);
  } catch (e: any) {
    error.value = e.response?.data?.detail || "Failed to execute scan";
    loading.value = false;
  }
}

async function downloadScanPDF(): Promise<void> {
  if (!currentScan.value?.output) return;
  try {
    const response = await axios.post("/api/reports/scan/pdf", {
      scan_type: currentScan.value.scan_type,
      target: currentScan.value.target,
      command: currentScan.value.command,
      results: currentScan.value.output,
    }, { responseType: "blob" });
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement("a");
    link.href = url;
    link.download = `Scan_${currentScan.value.scan_type.replace(/\s+/g, '_')}_${new Date().toISOString().slice(0, 10)}.pdf`;
    link.click();
    window.URL.revokeObjectURL(url);
  } catch {
    error.value = "Failed to download PDF";
  }
}

function formatTime(ts: string): string {
  return new Date(ts).toLocaleTimeString();
}

function viewHistoryScan(scan: ScanResult): void {
  currentScan.value = scan;
  activeTab.value = "custom";
}

onMounted(() => {
  loadPresets();
  loadHistory();
});
</script>

<template>
  <div class="space-y-4">
    <header class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold tracking-wide" style="color: var(--np-accent-primary)">
          Scanning
        </h1>
        <p class="text-xs text-[var(--np-muted-text)]">
          Network reconnaissance and scan management
        </p>
      </div>
    </header>

    <div class="relative">
      <div class="flex items-center border-b overflow-x-auto" style="border-color: var(--np-border)">
        <button
          v-for="tab in tabs"
          :key="tab.id"
          type="button"
          @click="activeTab = tab.id"
          class="relative px-5 py-3 text-xs uppercase tracking-wider font-medium transition-colors duration-200 whitespace-nowrap"
          :class="activeTab === tab.id
            ? 'text-[var(--np-accent-primary)]'
            : 'text-[var(--np-muted-text)] hover:text-[var(--np-text)]'"
        >
          {{ tab.label }}
          <span
            v-if="activeTab === tab.id"
            class="absolute bottom-0 left-0 right-0 h-0.5 rounded-t-full transition-all duration-300"
            :class="isNightshade ? 'bg-teal-400' : 'bg-amber-400'"
          ></span>
        </button>
      </div>

      <div class="mt-4 np-fade-in">
        <div v-if="activeTab === 'presets'" class="space-y-4">
          <div class="np-panel p-4">
            <h2 class="text-sm font-semibold uppercase tracking-wider mb-3" style="color: var(--np-accent-primary)">
              Quick Scan Presets
            </h2>
            <div class="mb-3">
              <label class="text-xs text-[var(--np-muted-text)]">Target IP/Hostname</label>
              <input
                v-model="target"
                type="text"
                placeholder="192.168.1.1 or example.com"
                class="mt-1 w-full rounded-md border px-3 py-2 text-sm bg-black/40 focus:outline-none focus:ring-1"
                style="border-color: var(--np-border); color: var(--np-text)"
              />
            </div>
            <div v-if="presets.length" class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              <button
                v-for="preset in presets"
                :key="preset.id"
                @click="selectPreset(preset)"
                class="rounded-lg border p-3 text-left transition-all hover:ring-1"
                :class="isNightshade
                  ? 'border-teal-400/30 bg-black/30 hover:bg-teal-500/10 hover:ring-teal-400/30'
                  : 'border-slate-600 bg-slate-800/50 hover:bg-slate-700/50 hover:ring-amber-400/30'"
              >
                <span class="block text-sm font-medium text-[var(--np-text)]">{{ preset.name }}</span>
                <span class="block text-[0.65rem] mt-1 text-[var(--np-muted-text)]">{{ preset.description }}</span>
                <code class="block mt-2 text-[0.6rem] font-mono" style="color: var(--np-accent-primary)">{{ preset.command }}</code>
              </button>
            </div>
            <p v-else class="text-sm text-[var(--np-muted-text)]">Loading presets...</p>
          </div>
        </div>

        <div v-else-if="activeTab === 'nse'" class="space-y-4">
          <div class="np-panel p-4">
            <h2 class="text-sm font-semibold uppercase tracking-wider mb-3" style="color: var(--np-accent-primary)">
              NSE Script Library
            </h2>
            <div class="flex flex-col sm:flex-row gap-3 mb-4">
              <div class="flex-1">
                <label class="text-xs text-[var(--np-muted-text)]">Target IP/Hostname</label>
                <input
                  v-model="target"
                  type="text"
                  placeholder="192.168.1.1 or example.com"
                  class="mt-1 w-full rounded-md border px-3 py-2 text-sm bg-black/40 focus:outline-none focus:ring-1"
                  style="border-color: var(--np-border); color: var(--np-text)"
                />
              </div>
              <div class="sm:w-48">
                <label class="text-xs text-[var(--np-muted-text)]">Category</label>
                <select
                  v-model="nseCategory"
                  class="mt-1 w-full rounded-md border px-3 py-2 text-sm bg-black/40 focus:outline-none focus:ring-1"
                  style="border-color: var(--np-border); color: var(--np-text)"
                >
                  <option v-for="cat in nseCategories" :key="cat" :value="cat">
                    {{ cat === 'all' ? 'All Categories' : cat }}
                  </option>
                </select>
              </div>
            </div>
            <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              <button
                v-for="script in filteredNseScripts"
                :key="script.name"
                @click="selectNseScript(script)"
                class="rounded-lg border p-3 text-left transition-all hover:ring-1"
                :class="isNightshade
                  ? 'border-teal-400/30 bg-black/30 hover:bg-teal-500/10 hover:ring-teal-400/30'
                  : 'border-slate-600 bg-slate-800/50 hover:bg-slate-700/50 hover:ring-amber-400/30'"
              >
                <div class="flex items-center justify-between mb-1">
                  <span class="text-sm font-semibold text-[var(--np-text)]">{{ script.name }}</span>
                  <span
                    class="text-[0.6rem] px-1.5 py-0.5 rounded-full font-medium"
                    :class="isNightshade
                      ? 'bg-teal-500/20 text-teal-300'
                      : 'bg-amber-500/20 text-amber-300'"
                  >{{ script.category }}</span>
                </div>
                <span class="block text-[0.65rem] mt-1 text-[var(--np-muted-text)]">{{ script.description }}</span>
                <code class="block mt-2 text-[0.6rem] font-mono" style="color: var(--np-accent-primary)">{{ script.command }}</code>
              </button>
            </div>
          </div>
        </div>

        <div v-else-if="activeTab === 'custom'" class="grid gap-4 lg:grid-cols-2">
          <div class="np-panel p-4 space-y-4">
            <h2 class="text-sm font-semibold uppercase tracking-wider" style="color: var(--np-accent-primary)">
              Smart Command Builder
            </h2>
            <div class="space-y-3">
              <div>
                <label class="text-xs text-[var(--np-muted-text)]">Target IP/Hostname</label>
                <input
                  v-model="target"
                  type="text"
                  placeholder="192.168.1.1 or example.com"
                  class="mt-1 w-full rounded-md border px-3 py-2 text-sm bg-black/40 focus:outline-none focus:ring-1"
                  style="border-color: var(--np-border); color: var(--np-text)"
                />
              </div>
              <div>
                <label class="text-xs text-[var(--np-muted-text)]">Describe your scan objective</label>
                <textarea
                  v-model="aiDescription"
                  rows="2"
                  placeholder="e.g., Run vulnerability scan with scripts, check for EternalBlue, stealth UDP scan..."
                  class="mt-1 w-full rounded-md border px-3 py-2 text-sm resize-none bg-black/40 focus:outline-none focus:ring-1"
                  style="border-color: var(--np-border); color: var(--np-text)"
                ></textarea>
              </div>
              <button
                @click="generateAICommand"
                :disabled="aiLoading"
                class="w-full rounded-md border px-4 py-2 text-sm font-medium transition-colors"
                :class="isNightshade
                  ? 'border-violet-400/50 bg-violet-500/20 text-violet-300 hover:bg-violet-500/30'
                  : 'border-amber-500/50 bg-amber-500/20 text-amber-300 hover:bg-amber-500/30'"
              >
                {{ aiLoading ? "Generating..." : "Generate Command" }}
              </button>
              <div v-if="aiExplanation" class="rounded-md border p-3 text-xs"
                :class="isNightshade ? 'border-violet-400/30 bg-violet-500/10 text-violet-200' : 'border-amber-500/30 bg-amber-500/10 text-amber-200'">
                <pre class="whitespace-pre-wrap font-mono">{{ aiExplanation }}</pre>
              </div>
            </div>

            <hr style="border-color: var(--np-border)" />

            <div>
              <label class="text-xs text-[var(--np-muted-text)]">Command</label>
              <input
                v-model="command"
                type="text"
                class="mt-1 w-full rounded-md border px-3 py-2 font-mono text-sm bg-black/40 focus:outline-none focus:ring-1"
                style="border-color: var(--np-border); color: var(--np-text)"
              />
            </div>

            <div class="flex items-center gap-3">
              <label class="flex items-center gap-2 text-xs text-[var(--np-muted-text)]">
                <input v-model="saveResults" type="checkbox" class="rounded" />
                Save results to file
              </label>
            </div>

            <button
              @click="executeScan"
              :disabled="loading || !target"
              class="w-full rounded-md px-4 py-2 text-sm font-medium transition-colors flex items-center justify-center gap-2"
              :class="loading
                ? 'bg-slate-600 text-slate-400 cursor-not-allowed'
                : isNightshade
                  ? 'bg-teal-500 text-black hover:bg-teal-400'
                  : 'bg-amber-500 text-black hover:bg-amber-400'"
            >
              <svg v-if="loading" class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              {{ loading ? "Scanning..." : "Execute Scan" }}
            </button>
            <p v-if="error" class="text-xs text-rose-400">{{ error }}</p>
          </div>

          <div class="np-panel p-4 space-y-3">
            <div class="flex items-center justify-between">
              <h2 class="text-sm font-semibold uppercase tracking-wider" style="color: var(--np-accent-primary)">
                Scan Results
              </h2>
              <button
                v-if="currentScan?.output"
                @click="downloadScanPDF"
                class="rounded-md border px-3 py-1 text-xs transition-colors"
                style="border-color: var(--np-border); color: var(--np-accent-primary)"
              >
                Download PDF
              </button>
            </div>
            <div v-if="currentScan" class="space-y-2">
              <div class="flex items-center gap-2 text-xs">
                <span
                  class="rounded px-2 py-0.5 font-medium"
                  :class="{
                    'bg-amber-500/20 text-amber-400': currentScan.status === 'running',
                    'bg-green-500/20 text-green-400': currentScan.status === 'completed',
                    'bg-rose-500/20 text-rose-400': currentScan.status === 'error' || currentScan.status === 'timeout',
                  }"
                >
                  {{ currentScan.status.toUpperCase() }}
                </span>
                <span class="text-[var(--np-muted-text)]">{{ currentScan.scan_type }}</span>
                <span class="text-[var(--np-muted-text)]">{{ currentScan.target }}</span>
              </div>
              <div class="max-h-[400px] overflow-auto rounded-md border p-3 font-mono text-xs bg-black/60"
                style="border-color: var(--np-border); color: var(--np-text)">
                <pre v-if="currentScan.output" class="whitespace-pre-wrap">{{ currentScan.output }}</pre>
                <div v-else class="flex flex-col items-center justify-center py-8 gap-3">
                  <svg class="w-8 h-8 animate-spin" style="color: var(--np-accent-primary)" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  <span class="text-[var(--np-muted-text)]">Scanning in progress...</span>
                </div>
              </div>
            </div>
            <div v-else class="py-8 text-center text-sm text-[var(--np-muted-text)]">
              Configure and execute a scan to see results
            </div>
          </div>
        </div>

        <div v-else-if="activeTab === 'nettools'" class="space-y-4">
          <div class="flex items-center gap-2 flex-wrap mb-2">
            <button
              v-for="tool in netTools"
              :key="tool.id"
              type="button"
              @click="activeNetTool = tool.id"
              class="rounded-full px-4 py-1.5 text-xs font-medium transition-all duration-200"
              :class="activeNetTool === tool.id
                ? isNightshade
                  ? 'bg-teal-500/30 text-teal-300 border border-teal-400/50'
                  : 'bg-amber-500/30 text-amber-300 border border-amber-400/50'
                : isNightshade
                  ? 'bg-black/30 text-[var(--np-muted-text)] border border-teal-400/10 hover:border-teal-400/30 hover:text-teal-300'
                  : 'bg-slate-800/50 text-[var(--np-muted-text)] border border-slate-600/50 hover:border-amber-400/30 hover:text-amber-300'"
            >
              {{ tool.label }}
            </button>
          </div>

          <div v-if="activeNetTool === 'traceroute'" class="np-panel p-4">
            <h2 class="text-sm font-semibold uppercase tracking-wider mb-3" style="color: var(--np-accent-primary)">
              Traceroute
            </h2>
            <div class="flex flex-col sm:flex-row gap-3 mb-4">
              <div class="flex-1">
                <label class="text-xs text-[var(--np-muted-text)]">Target IP/Hostname</label>
                <input
                  v-model="tracerouteTarget"
                  type="text"
                  placeholder="8.8.8.8 or example.com"
                  class="mt-1 w-full rounded-md border px-3 py-2 text-sm bg-black/40 focus:outline-none focus:ring-1"
                  style="border-color: var(--np-border); color: var(--np-text)"
                  @keyup.enter="runTraceroute"
                />
              </div>
              <div class="sm:self-end">
                <button
                  @click="runTraceroute"
                  :disabled="tracerouteLoading || !tracerouteTarget.trim()"
                  class="np-cyber-btn rounded-md px-5 py-2 text-sm flex items-center gap-2"
                  :class="tracerouteLoading ? 'opacity-50 cursor-not-allowed' : ''"
                >
                  <svg v-if="tracerouteLoading" class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  {{ tracerouteLoading ? "Tracing..." : "Run Traceroute" }}
                </button>
              </div>
            </div>

            <p v-if="tracerouteError" class="text-xs text-rose-400 mb-3">{{ tracerouteError }}</p>

            <div v-if="tracerouteLoading && !tracerouteHops.length" class="flex flex-col items-center justify-center py-12 gap-3">
              <svg class="w-8 h-8 animate-spin" style="color: var(--np-accent-primary)" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              <span class="text-sm text-[var(--np-muted-text)]">Running traceroute...</span>
            </div>

            <div v-if="tracerouteHops.length" class="space-y-0">
              <div
                v-for="(hop, idx) in tracerouteHops"
                :key="hop.hop"
                class="relative"
              >
                <div
                  v-if="idx > 0"
                  class="absolute left-5 -top-2 w-px h-4 border-l-2 border-dashed"
                  :class="isNightshade ? 'border-teal-400/30' : 'border-slate-600'"
                ></div>
                <div
                  class="flex items-center gap-3 rounded-lg border p-3 transition-colors"
                  :class="isNightshade
                    ? 'border-teal-400/20 bg-black/30'
                    : 'border-slate-700 bg-slate-800/50'"
                >
                  <div
                    class="flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center text-xs font-bold"
                    :class="isNightshade
                      ? 'bg-teal-500/20 text-teal-300 border border-teal-400/30'
                      : 'bg-amber-500/20 text-amber-300 border border-amber-400/30'"
                  >
                    {{ hop.hop }}
                  </div>
                  <div class="flex-1 min-w-0">
                    <div v-if="hop.is_timeout" class="text-sm text-[var(--np-muted-text)] font-mono">
                      * * *
                    </div>
                    <div v-else>
                      <span class="text-sm font-mono font-medium text-[var(--np-text)]">{{ hop.ip || 'Unknown' }}</span>
                    </div>
                  </div>
                  <div v-if="!hop.is_timeout && hop.rtt_ms" class="flex items-center gap-2 flex-shrink-0">
                    <span
                      v-for="(rtt, ri) in hop.rtt_ms"
                      :key="ri"
                      class="text-xs font-mono font-medium"
                      :class="rttColor(rtt)"
                    >{{ rtt.toFixed(1) }}ms</span>
                  </div>
                  <div v-else-if="hop.is_timeout" class="flex-shrink-0">
                    <span class="text-xs text-[var(--np-muted-text)]">timeout</span>
                  </div>
                </div>
              </div>
            </div>

            <div v-if="tracerouteRawOutput" class="mt-4">
              <button
                @click="tracerouteShowRaw = !tracerouteShowRaw"
                class="text-xs font-medium transition-colors"
                style="color: var(--np-accent-primary)"
              >
                {{ tracerouteShowRaw ? 'Hide' : 'Show' }} Raw Output
              </button>
              <div v-if="tracerouteShowRaw" class="mt-2 rounded-md border p-3 bg-black/60 max-h-64 overflow-auto"
                style="border-color: var(--np-border)">
                <pre class="text-xs font-mono whitespace-pre-wrap text-[var(--np-text)]">{{ tracerouteRawOutput }}</pre>
              </div>
            </div>

            <div v-if="!tracerouteHops.length && !tracerouteLoading && !tracerouteError" class="py-8 text-center text-sm text-[var(--np-muted-text)]">
              Enter a target and run traceroute to visualize the network path
            </div>
          </div>

          <div v-else-if="activeNetTool === 'ping'" class="np-panel p-4">
            <h2 class="text-sm font-semibold uppercase tracking-wider mb-3" style="color: var(--np-accent-primary)">
              Ping Sweep
            </h2>
            <div class="flex flex-col sm:flex-row gap-3 mb-4">
              <div class="flex-1">
                <label class="text-xs text-[var(--np-muted-text)]">Target Subnet</label>
                <input
                  v-model="pingSweepTarget"
                  type="text"
                  placeholder="192.168.1.0/24"
                  class="mt-1 w-full rounded-md border px-3 py-2 text-sm bg-black/40 focus:outline-none focus:ring-1"
                  style="border-color: var(--np-border); color: var(--np-text)"
                  @keyup.enter="runPingSweep"
                />
              </div>
              <div class="sm:self-end">
                <button
                  @click="runPingSweep"
                  :disabled="pingSweepLoading || !pingSweepTarget.trim()"
                  class="rounded-md px-5 py-2 text-sm font-medium flex items-center gap-2 transition-colors"
                  :class="pingSweepLoading
                    ? 'bg-slate-600 text-slate-400 cursor-not-allowed'
                    : isNightshade
                      ? 'bg-teal-500 text-black hover:bg-teal-400'
                      : 'bg-amber-500 text-black hover:bg-amber-400'"
                >
                  <svg v-if="pingSweepLoading" class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  {{ pingSweepLoading ? "Sweeping..." : "Run Sweep" }}
                </button>
              </div>
            </div>

            <p v-if="pingSweepError" class="text-xs text-rose-400 mb-3">{{ pingSweepError }}</p>

            <div v-if="pingSweepLoading && !pingSweepResults.length" class="flex flex-col items-center justify-center py-12 gap-3">
              <svg class="w-8 h-8 animate-spin" style="color: var(--np-accent-primary)" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              <span class="text-sm text-[var(--np-muted-text)]">Running ping sweep...</span>
            </div>

            <div v-if="pingSweepResults.length" class="space-y-2">
              <div class="text-xs text-[var(--np-muted-text)] mb-2">{{ pingSweepResults.length }} host(s) discovered</div>
              <div
                v-for="host in pingSweepResults"
                :key="host.ip"
                class="flex items-center justify-between rounded-lg border p-3 transition-colors"
                :class="isNightshade
                  ? 'border-teal-400/20 bg-black/30'
                  : 'border-slate-700 bg-slate-800/50'"
              >
                <div class="flex items-center gap-3">
                  <span
                    class="h-2.5 w-2.5 rounded-full"
                    :class="host.status === 'up' ? (isNightshade ? 'bg-emerald-400' : 'bg-green-500') : 'bg-rose-400'"
                  ></span>
                  <span class="text-sm font-mono font-medium text-[var(--np-text)]">{{ host.ip }}</span>
                </div>
                <div class="flex items-center gap-3">
                  <span v-if="host.latency" class="text-xs font-mono text-[var(--np-muted-text)]">{{ host.latency }}</span>
                  <span
                    class="text-xs px-2 py-0.5 rounded-full font-medium"
                    :class="host.status === 'up'
                      ? (isNightshade ? 'bg-emerald-500/20 text-emerald-400' : 'bg-green-500/20 text-green-400')
                      : 'bg-rose-500/20 text-rose-400'"
                  >{{ host.status }}</span>
                </div>
              </div>
            </div>

            <div v-if="!pingSweepResults.length && !pingSweepLoading && !pingSweepError" class="py-8 text-center text-sm text-[var(--np-muted-text)]">
              Enter a subnet and run sweep to discover live hosts
            </div>
          </div>

          <div v-else-if="activeNetTool === 'dns'" class="np-panel p-4">
            <h2 class="text-sm font-semibold uppercase tracking-wider mb-3" style="color: var(--np-accent-primary)">
              DNS Lookup
            </h2>
            <div class="flex flex-col sm:flex-row gap-3 mb-4">
              <div class="flex-1">
                <label class="text-xs text-[var(--np-muted-text)]">Hostname</label>
                <input
                  v-model="dnsTarget"
                  type="text"
                  placeholder="example.com"
                  class="mt-1 w-full rounded-md border px-3 py-2 text-sm bg-black/40 focus:outline-none focus:ring-1"
                  style="border-color: var(--np-border); color: var(--np-text)"
                  @keyup.enter="runDnsLookup"
                />
              </div>
              <div class="sm:self-end">
                <button
                  @click="runDnsLookup"
                  :disabled="dnsLoading || !dnsTarget.trim()"
                  class="rounded-md px-5 py-2 text-sm font-medium flex items-center gap-2 transition-colors"
                  :class="dnsLoading
                    ? 'bg-slate-600 text-slate-400 cursor-not-allowed'
                    : isNightshade
                      ? 'bg-teal-500 text-black hover:bg-teal-400'
                      : 'bg-amber-500 text-black hover:bg-amber-400'"
                >
                  <svg v-if="dnsLoading" class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  {{ dnsLoading ? "Looking up..." : "Lookup" }}
                </button>
              </div>
            </div>

            <p v-if="dnsError" class="text-xs text-rose-400 mb-3">{{ dnsError }}</p>

            <div v-if="dnsLoading && !dnsResults" class="flex flex-col items-center justify-center py-12 gap-3">
              <svg class="w-8 h-8 animate-spin" style="color: var(--np-accent-primary)" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              <span class="text-sm text-[var(--np-muted-text)]">Running DNS lookup...</span>
            </div>

            <div v-if="dnsResults" class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              <div
                v-for="(records, recordType) in dnsResults"
                :key="recordType"
                class="rounded-lg border p-3"
                :class="isNightshade
                  ? 'border-teal-400/20 bg-black/30'
                  : 'border-slate-700 bg-slate-800/50'"
              >
                <div class="text-xs font-semibold uppercase tracking-wider mb-2" style="color: var(--np-accent-primary)">
                  {{ recordType }}
                </div>
                <div v-if="records.length" class="space-y-1">
                  <div
                    v-for="(record, ri) in records"
                    :key="ri"
                    class="text-xs font-mono text-[var(--np-text)]"
                  >{{ record }}</div>
                </div>
                <div v-else class="text-xs text-[var(--np-muted-text)]">No records</div>
              </div>
            </div>

            <div v-if="!dnsResults && !dnsLoading && !dnsError" class="py-8 text-center text-sm text-[var(--np-muted-text)]">
              Enter a hostname and run lookup to view DNS records
            </div>
          </div>

          <div v-else-if="activeNetTool === 'whois'" class="np-panel p-4">
            <h2 class="text-sm font-semibold uppercase tracking-wider mb-3" style="color: var(--np-accent-primary)">
              Whois Lookup
            </h2>
            <div class="flex flex-col sm:flex-row gap-3 mb-4">
              <div class="flex-1">
                <label class="text-xs text-[var(--np-muted-text)]">IP or Domain</label>
                <input
                  v-model="whoisTarget"
                  type="text"
                  placeholder="example.com or 8.8.8.8"
                  class="mt-1 w-full rounded-md border px-3 py-2 text-sm bg-black/40 focus:outline-none focus:ring-1"
                  style="border-color: var(--np-border); color: var(--np-text)"
                  @keyup.enter="runWhois"
                />
              </div>
              <div class="sm:self-end">
                <button
                  @click="runWhois"
                  :disabled="whoisLoading || !whoisTarget.trim()"
                  class="rounded-md px-5 py-2 text-sm font-medium flex items-center gap-2 transition-colors"
                  :class="whoisLoading
                    ? 'bg-slate-600 text-slate-400 cursor-not-allowed'
                    : isNightshade
                      ? 'bg-teal-500 text-black hover:bg-teal-400'
                      : 'bg-amber-500 text-black hover:bg-amber-400'"
                >
                  <svg v-if="whoisLoading" class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  {{ whoisLoading ? "Looking up..." : "Lookup" }}
                </button>
              </div>
            </div>

            <div v-if="whoisError" class="rounded-md border border-rose-400/30 bg-rose-500/10 p-3 mb-3">
              <div class="flex items-start gap-2">
                <svg class="w-4 h-4 text-rose-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
                </svg>
                <p class="text-xs text-rose-300">{{ whoisError }}</p>
              </div>
            </div>

            <div v-if="whoisLoading && !whoisResult" class="flex flex-col items-center justify-center py-12 gap-3">
              <svg class="w-8 h-8 animate-spin" style="color: var(--np-accent-primary)" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              <span class="text-sm text-[var(--np-muted-text)]">Running whois lookup...</span>
            </div>

            <div v-if="whoisResult" class="rounded-md border p-3 bg-black/60 max-h-96 overflow-auto"
              style="border-color: var(--np-border)">
              <pre class="text-xs font-mono whitespace-pre-wrap text-[var(--np-text)]">{{ whoisResult }}</pre>
            </div>

            <div v-if="!whoisResult && !whoisLoading && !whoisError" class="py-8 text-center text-sm text-[var(--np-muted-text)]">
              Enter an IP or domain to view whois information
            </div>
          </div>

          <div v-else-if="activeNetTool === 'capture'" class="np-panel p-4">
            <h2 class="text-sm font-semibold uppercase tracking-wider mb-3" style="color: var(--np-accent-primary)">
              Packet Capture
            </h2>
            <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 mb-4">
              <div>
                <label class="text-xs text-[var(--np-muted-text)]">Interface</label>
                <select
                  v-model="captureInterface"
                  class="mt-1 w-full rounded-md border px-3 py-2 text-sm bg-black/40 focus:outline-none focus:ring-1"
                  style="border-color: var(--np-border); color: var(--np-text)"
                >
                  <option value="any">any</option>
                  <option value="eth0">eth0</option>
                  <option value="wlan0">wlan0</option>
                </select>
              </div>
              <div>
                <label class="text-xs text-[var(--np-muted-text)]">BPF Filter</label>
                <input
                  v-model="captureFilter"
                  type="text"
                  placeholder="port 80 or host 192.168.1.1"
                  class="mt-1 w-full rounded-md border px-3 py-2 text-sm bg-black/40 focus:outline-none focus:ring-1"
                  style="border-color: var(--np-border); color: var(--np-text)"
                />
              </div>
              <div>
                <label class="text-xs text-[var(--np-muted-text)]">Duration (sec)</label>
                <input
                  v-model.number="captureDuration"
                  type="number"
                  min="1"
                  max="60"
                  class="mt-1 w-full rounded-md border px-3 py-2 text-sm bg-black/40 focus:outline-none focus:ring-1"
                  style="border-color: var(--np-border); color: var(--np-text)"
                />
              </div>
              <div>
                <label class="text-xs text-[var(--np-muted-text)]">Packet Count</label>
                <input
                  v-model.number="captureCount"
                  type="number"
                  min="1"
                  max="1000"
                  class="mt-1 w-full rounded-md border px-3 py-2 text-sm bg-black/40 focus:outline-none focus:ring-1"
                  style="border-color: var(--np-border); color: var(--np-text)"
                />
              </div>
            </div>

            <button
              @click="runCapture"
              :disabled="captureLoading"
              class="rounded-md px-5 py-2 text-sm font-medium flex items-center gap-2 transition-colors mb-4"
              :class="captureLoading
                ? 'bg-slate-600 text-slate-400 cursor-not-allowed'
                : isNightshade
                  ? 'bg-teal-500 text-black hover:bg-teal-400'
                  : 'bg-amber-500 text-black hover:bg-amber-400'"
            >
              <svg v-if="captureLoading" class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              {{ captureLoading ? "Capturing..." : "Start Capture" }}
            </button>

            <p v-if="captureError" class="text-xs text-rose-400 mb-3">{{ captureError }}</p>

            <div v-if="captureLoading && !capturePackets.length" class="flex flex-col items-center justify-center py-12 gap-3">
              <svg class="w-8 h-8 animate-spin" style="color: var(--np-accent-primary)" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              <span class="text-sm text-[var(--np-muted-text)]">Capturing packets...</span>
            </div>

            <div v-if="capturePackets.length" class="space-y-3">
              <div class="text-xs text-[var(--np-muted-text)] mb-2">{{ capturePackets.length }} packet(s) captured</div>
              <div class="overflow-x-auto rounded-md border bg-black/60" style="border-color: var(--np-border)">
                <table class="w-full text-xs">
                  <thead>
                    <tr class="border-b" style="border-color: var(--np-border)">
                      <th class="px-3 py-2 text-left font-semibold" style="color: var(--np-accent-primary)">Timestamp</th>
                      <th class="px-3 py-2 text-left font-semibold" style="color: var(--np-accent-primary)">Source</th>
                      <th class="px-3 py-2 text-left font-semibold" style="color: var(--np-accent-primary)">Destination</th>
                      <th class="px-3 py-2 text-left font-semibold" style="color: var(--np-accent-primary)">Protocol</th>
                      <th class="px-3 py-2 text-left font-semibold" style="color: var(--np-accent-primary)">Length</th>
                      <th class="px-3 py-2 text-left font-semibold" style="color: var(--np-accent-primary)">Info</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr
                      v-for="(pkt, pi) in capturePackets"
                      :key="pi"
                      class="border-b transition-colors"
                      :class="isNightshade ? 'border-teal-400/10 hover:bg-teal-500/5' : 'border-slate-700/50 hover:bg-slate-700/30'"
                      style="border-color: var(--np-border)"
                    >
                      <td class="px-3 py-1.5 font-mono text-[var(--np-text)]">{{ pkt.timestamp }}</td>
                      <td class="px-3 py-1.5 font-mono text-[var(--np-text)]">{{ pkt.source }}</td>
                      <td class="px-3 py-1.5 font-mono text-[var(--np-text)]">{{ pkt.destination }}</td>
                      <td class="px-3 py-1.5">
                        <span
                          class="px-1.5 py-0.5 rounded text-[0.6rem] font-medium"
                          :class="isNightshade
                            ? 'bg-teal-500/20 text-teal-300'
                            : 'bg-amber-500/20 text-amber-300'"
                        >{{ pkt.protocol }}</span>
                      </td>
                      <td class="px-3 py-1.5 font-mono text-[var(--np-muted-text)]">{{ pkt.length }}</td>
                      <td class="px-3 py-1.5 text-[var(--np-muted-text)] max-w-xs truncate">{{ pkt.info }}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            <div v-if="captureRawOutput" class="mt-4">
              <button
                @click="captureShowRaw = !captureShowRaw"
                class="text-xs font-medium transition-colors"
                style="color: var(--np-accent-primary)"
              >
                {{ captureShowRaw ? 'Hide' : 'Show' }} Raw Output
              </button>
              <div v-if="captureShowRaw" class="mt-2 rounded-md border p-3 bg-black/60 max-h-64 overflow-auto"
                style="border-color: var(--np-border)">
                <pre class="text-xs font-mono whitespace-pre-wrap text-[var(--np-text)]">{{ captureRawOutput }}</pre>
              </div>
            </div>

            <div v-if="!capturePackets.length && !captureLoading && !captureError" class="py-8 text-center text-sm text-[var(--np-muted-text)]">
              Configure capture settings and start capturing packets
            </div>
          </div>
        </div>

        <div v-else-if="activeTab === 'history'" class="np-panel p-4">
          <h2 class="mb-3 text-sm font-semibold uppercase tracking-wider" style="color: var(--np-accent-primary)">
            Scan History
          </h2>
          <div v-if="scanHistory.length" class="space-y-2 max-h-96 overflow-auto">
            <div
              v-for="scan in scanHistory"
              :key="scan.id"
              @click="viewHistoryScan(scan)"
              class="flex items-center justify-between rounded-md border p-3 cursor-pointer transition-colors"
              :class="isNightshade
                ? 'border-teal-400/20 hover:bg-teal-500/10'
                : 'border-slate-700 hover:bg-slate-700/50'"
            >
              <div class="flex items-center gap-3">
                <span
                  class="h-2 w-2 rounded-full"
                  :class="{
                    'bg-emerald-400': scan.status === 'completed',
                    'bg-amber-400': scan.status === 'running',
                    'bg-rose-400': scan.status === 'error',
                  }"
                ></span>
                <span class="text-xs font-medium text-[var(--np-text)]">{{ scan.scan_type }}</span>
                <span class="text-xs text-[var(--np-muted-text)]">{{ scan.target }}</span>
              </div>
              <span class="text-xs text-[var(--np-muted-text)]">{{ formatTime(scan.started_at) }}</span>
            </div>
          </div>
          <div v-else class="py-8 text-center text-sm text-[var(--np-muted-text)]">
            No scans yet
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
