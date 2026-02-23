<script setup lang="ts">
import axios from "axios";
import { computed, onMounted, ref } from "vue";

type Theme = "nightshade" | "sysadmin";

interface Props {
  theme: Theme;
}

interface Playbook {
  id: string;
  label: string;
  scriptName: string;
  description: string;
  category: string;
  icon: string;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  (e: "toast", type: "success" | "error" | "warning" | "info", message: string): void;
}>();

const canRun = computed(() => true);
const isNightshade = computed(() => props.theme === "nightshade");

interface NmapPlaybook extends Playbook {
  nmapCommand: string;
}

const allPlaybooks: NmapPlaybook[] = [
  { id: "quick-scan", label: "Quick Scan", scriptName: "nmap", nmapCommand: "nmap -T4 -F", description: "Fast scan of top 100 ports.", category: "Discovery", icon: "search" },
  { id: "full-port", label: "Full Port Scan", scriptName: "nmap", nmapCommand: "nmap -p- -T4", description: "All 65535 TCP ports.", category: "Discovery", icon: "search" },
  { id: "version-detect", label: "Version Detection", scriptName: "nmap", nmapCommand: "nmap -sV -T3", description: "Detect service versions.", category: "Discovery", icon: "search" },
  { id: "os-detect", label: "OS Detection", scriptName: "nmap", nmapCommand: "nmap -O -T3", description: "Detect operating system.", category: "Discovery", icon: "search" },
  { id: "stealth-scan", label: "Stealth Scan", scriptName: "nmap", nmapCommand: "nmap -sS -T2 -n", description: "SYN scan, slower, no DNS.", category: "Reconnaissance", icon: "search" },
  { id: "udp-scan", label: "UDP Scan", scriptName: "nmap", nmapCommand: "nmap -sU --top-ports 100", description: "Top 100 UDP ports.", category: "Reconnaissance", icon: "wifi" },
  { id: "vuln-scan", label: "Vulnerability Scan", scriptName: "nmap", nmapCommand: "nmap -sV --script=vuln", description: "Check for known vulnerabilities.", category: "Security Audit", icon: "shield" },
  { id: "aggressive-scan", label: "Aggressive Scan", scriptName: "nmap", nmapCommand: "nmap -A -T4", description: "OS, version, scripts, traceroute.", category: "Security Audit", icon: "zap" },
  { id: "web-scan", label: "Web Server Scan", scriptName: "nmap", nmapCommand: "nmap -p 80,443,8080,8443 -sV", description: "Web server enumeration.", category: "Reconnaissance", icon: "globe" },
  { id: "smb-scan", label: "SMB Audit", scriptName: "nmap", nmapCommand: "nmap -p 139,445 --script=smb-enum-shares", description: "Windows share enumeration.", category: "Reconnaissance", icon: "folder" },
  { id: "ssl-check", label: "SSL/TLS Check", scriptName: "nmap", nmapCommand: "nmap -p 443 --script=ssl-cert", description: "Check SSL certificate info.", category: "Security Audit", icon: "lock" },
  { id: "ping-sweep", label: "Ping Sweep", scriptName: "nmap", nmapCommand: "nmap -sn", description: "Discover live hosts without port scan.", category: "Discovery", icon: "wifi" },
];

const categories = computed(() => [...new Set(allPlaybooks.map(p => p.category))]);
const selectedCategory = ref<string>("All");

const selectedPlaybookIds = ref<string[]>([]);
const targetIp = ref("");

function togglePlaybook(id: string) {
  const idx = selectedPlaybookIds.value.indexOf(id);
  if (idx === -1) {
    selectedPlaybookIds.value.push(id);
  } else {
    selectedPlaybookIds.value.splice(idx, 1);
  }
}

function isSelected(id: string): boolean {
  return selectedPlaybookIds.value.includes(id);
}

function selectAll() {
  selectedPlaybookIds.value = filteredPlaybooks.value.map(pb => pb.id);
}

function clearSelection() {
  selectedPlaybookIds.value = [];
}

// Status
const running = ref(false);
const statusLines = ref<string[]>([]);

function log(message: string): void {
  const now = new Date();
  const ts = now.toISOString().split("T")[1]?.slice(0, 8) ?? "";
  statusLines.value.push(`[${ts}] ${message}`);
}

const filteredPlaybooks = computed(() => {
  if (selectedCategory.value === "All") {
    return allPlaybooks;
  }
  return allPlaybooks.filter((pb) => pb.category === selectedCategory.value);
});

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

const selectedPlaybooks = computed<NmapPlaybook[]>(() => {
  return allPlaybooks.filter((pb) => selectedPlaybookIds.value.includes(pb.id));
});

const scanIds = ref<string[]>([]);
const completedScans = ref<number>(0);
const totalScans = ref<number>(0);

async function runPlaybookScenario(): Promise<void> {
  if (!canRun.value) {
    return;
  }
  const playbooks = selectedPlaybooks.value;
  if (playbooks.length === 0) {
    log("Select at least one playbook first.");
    return;
  }
  if (!targetIp.value.trim()) {
    log("Enter a target IP or hostname first.");
    return;
  }

  running.value = true;
  statusLines.value = [];
  scanIds.value = [];
  completedScans.value = 0;
  totalScans.value = playbooks.length;

  const playbookNames = playbooks.map(p => p.label).join(", ");
  log(`Starting ${playbooks.length} scan(s): ${playbookNames}`);
  log(`Target: ${targetIp.value.trim()}`);

  try {
    for (const pb of playbooks) {
      log(`Executing ${pb.label}...`);
      try {
        const { data } = await axios.post<ScanResult>("/api/nmap/execute", {
          command: pb.nmapCommand,
          target: targetIp.value.trim(),
          save_results: true,
        });
        scanIds.value.push(data.id);
        log(`  -> Started scan #${data.id}`);
      } catch (e: any) {
        log(`  -> Failed: ${e.response?.data?.detail || "Unknown error"}`);
      }
    }

    log(`Scans initiated: ${scanIds.value.length}/${playbooks.length}`);
    
    if (scanIds.value.length === 0) {
      running.value = false;
      emit("toast", "error", "All scans failed to start");
      return;
    }

    log("Waiting for scans to complete...");
    pollScans();
  } catch {
    log("Failed to start playbook scenario.");
    running.value = false;
    emit("toast", "error", "Failed to start playbook scenario");
  }
}

async function pollScans(): Promise<void> {
  const pendingIds = [...scanIds.value];
  const completedIds = new Set<string>();
  
  const poll = async () => {
    for (const scanId of pendingIds) {
      if (completedIds.has(scanId)) continue;
      
      try {
        const { data } = await axios.get<ScanResult>(`/api/nmap/result/${scanId}`);
        
        if (data.status === "completed" || data.status === "error" || data.status === "timeout") {
          completedIds.add(scanId);
          completedScans.value = completedIds.size;
          
          if (data.status === "completed") {
            log(`Scan #${scanId} completed: ${data.scan_type}`);
          } else {
            log(`Scan #${scanId} ${data.status}`);
          }
        }
      } catch {
        // Continue polling
      }
    }
    
    if (completedIds.size < pendingIds.length) {
      log(`Progress: ${completedIds.size}/${pendingIds.length} scans complete`);
      setTimeout(poll, 3000);
    } else {
      log(`All ${pendingIds.length} scan(s) completed!`);
      running.value = false;
      emit("toast", "success", `${pendingIds.length} scan(s) completed successfully`);
    }
  };
  
  setTimeout(poll, 3000);
}

onMounted(() => {
  // No script settings needed - all scripts are available
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
          :class="isNightshade ? 'text-teal-300' : 'text-amber-400'"
        >
          Use on networks you own or control
        </span>
      </header>

      <div class="space-y-3 text-xs">
        <div
          class="rounded-md border p-3"
          :class="isNightshade ? 'border-teal-400/30 bg-black/50' : 'border-amber-500/30 bg-slate-800/50'"
        >
          <div class="flex items-center justify-between mb-3">
            <div class="flex items-center gap-3">
              <p
                class="text-[0.7rem] uppercase tracking-[0.16em]"
                :class="isNightshade ? 'text-teal-200' : 'text-amber-300'"
              >
                Select Playbooks
              </p>
              <span 
                v-if="selectedPlaybookIds.length > 0"
                class="px-2 py-0.5 rounded-full text-[0.65rem] font-medium"
                :class="isNightshade ? 'bg-emerald-500/30 text-emerald-200' : 'bg-amber-500/30 text-amber-200'"
              >
                {{ selectedPlaybookIds.length }} selected
              </span>
            </div>
            <div class="flex items-center gap-2">
              <button
                type="button"
                @click="selectAll"
                class="px-2 py-1 rounded text-[0.65rem]"
                :class="isNightshade 
                  ? 'text-teal-300 hover:bg-teal-400/20' 
                  : 'text-amber-300 hover:bg-amber-500/20'"
              >
                Select All
              </button>
              <button
                type="button"
                @click="clearSelection"
                class="px-2 py-1 rounded text-[0.65rem]"
                :class="isNightshade 
                  ? 'text-teal-300 hover:bg-teal-400/20' 
                  : 'text-amber-300 hover:bg-amber-500/20'"
              >
                Clear
              </button>
              <select
                v-model="selectedCategory"
                class="rounded border px-2 py-1 text-[0.7rem]"
                :class="isNightshade 
                  ? 'border-teal-400/40 bg-black/70 text-teal-100' 
                  : 'border-amber-500/40 bg-slate-700 text-slate-200'"
              >
                <option value="All">All Categories</option>
                <option v-for="cat in categories" :key="cat" :value="cat">{{ cat }}</option>
              </select>
            </div>
          </div>

          <div class="grid gap-2 md:grid-cols-2 lg:grid-cols-3">
            <button
              v-for="pb in filteredPlaybooks"
              :key="pb.id"
              type="button"
              @click="togglePlaybook(pb.id)"
              class="rounded-lg border p-3 text-left transition-all"
              :class="[
                isSelected(pb.id)
                  ? isNightshade
                    ? 'border-emerald-400/60 bg-emerald-500/20 ring-1 ring-emerald-400/30'
                    : 'border-amber-500 bg-amber-500/20 ring-1 ring-amber-500/30'
                  : isNightshade
                    ? 'border-teal-400/30 bg-black/30 hover:bg-teal-500/10 hover:border-teal-400/50'
                    : 'border-slate-600 bg-slate-700/50 hover:bg-slate-600/50 hover:border-amber-500/50'
              ]"
            >
              <div class="flex items-start gap-2">
                <div 
                  class="w-5 h-5 rounded border flex items-center justify-center flex-shrink-0 mt-0.5"
                  :class="isSelected(pb.id)
                    ? (isNightshade ? 'border-emerald-400 bg-emerald-500/40' : 'border-amber-400 bg-amber-500/40')
                    : (isNightshade ? 'border-teal-400/40 bg-black/50' : 'border-slate-500 bg-slate-700')"
                >
                  <span v-if="isSelected(pb.id)" class="text-[0.7rem]">✓</span>
                </div>
                <div 
                  class="w-8 h-8 rounded-md flex items-center justify-center flex-shrink-0"
                  :class="isNightshade ? 'bg-teal-400/20' : 'bg-amber-500/20'"
                >
                  <span class="text-xs" :class="isNightshade ? 'text-teal-400' : 'text-amber-400'">
                    {{ pb.icon === 'zap' ? '⚡' : pb.icon === 'search' ? '🔍' : pb.icon === 'shield' ? '🛡️' : pb.icon === 'globe' ? '🌐' : pb.icon === 'lock' ? '🔒' : pb.icon === 'activity' ? '📊' : pb.icon === 'save' ? '💾' : pb.icon === 'power' ? '⏻' : '📋' }}
                  </span>
                </div>
                <div class="flex-1 min-w-0">
                  <span 
                    class="block font-semibold text-[0.75rem]"
                    :class="isSelected(pb.id) 
                      ? (isNightshade ? 'text-emerald-200' : 'text-amber-200') 
                      : (isNightshade ? 'text-teal-100' : 'text-slate-200')"
                  >
                    {{ pb.label }}
                  </span>
                  <span
                    class="block text-[0.65rem] mt-0.5 line-clamp-2"
                    :class="isNightshade ? 'text-teal-100/60' : 'text-slate-400'"
                  >
                    {{ pb.description }}
                  </span>
                  <span
                    class="inline-block mt-1 px-1.5 py-0.5 rounded text-[0.55rem] uppercase tracking-wide"
                    :class="isNightshade ? 'bg-teal-400/10 text-teal-300' : 'bg-amber-500/10 text-amber-300'"
                  >
                    {{ pb.category }}
                  </span>
                </div>
              </div>
            </button>
          </div>
        </div>

        <div
          class="rounded-md border p-3"
          :class="isNightshade ? 'border-teal-400/30 bg-black/50' : 'border-amber-500/30 bg-slate-800/50'"
        >
          <p
            class="text-[0.7rem] uppercase tracking-[0.16em]"
            :class="isNightshade ? 'text-teal-200' : 'text-amber-300'"
          >
            Target
          </p>
          <div class="mt-2">
            <label class="text-[0.7rem] text-[var(--np-muted-text)]">
              Target IP / Hostname / CIDR
              <input
                v-model="targetIp"
                type="text"
                class="mt-1 w-full rounded-md border px-2 py-1 text-[0.75rem]
                       focus:outline-none focus:ring-1"
                :class="isNightshade
                  ? 'border-teal-400/40 bg-black/70 text-teal-100 focus:ring-teal-400'
                  : 'border-amber-500/40 bg-slate-700 text-slate-200 focus:ring-amber-500'"
                placeholder="192.168.1.1 or 10.0.0.0/24"
              />
            </label>
          </div>

          <div class="mt-3 flex items-center justify-between text-[0.7rem]">
            <div
              :class="isNightshade ? 'text-teal-100/80' : 'text-slate-400'"
            >
              <p>
                Playbooks can generate aggressive or malformed traffic. Use only on networks you own or control.
              </p>
            </div>
            <button
              type="button"
              @click="runPlaybookScenario"
              class="rounded border px-3 py-1.5 text-[0.75rem] font-medium"
              :class="[
                isNightshade
                  ? 'border-emerald-400/60 bg-emerald-500/20 text-emerald-200 hover:bg-emerald-500/30'
                  : 'border-amber-500 bg-amber-500/20 text-amber-200 hover:bg-amber-500/30'
              ]"
              :disabled="running || selectedPlaybookIds.length === 0"
            >
              {{ running ? "Running scenario..." : selectedPlaybookIds.length > 1 ? `Run ${selectedPlaybookIds.length} playbooks` : "Run playbook" }}
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
          :class="isNightshade ? 'border-teal-400/30 bg-black/60' : 'border-amber-500/30 bg-slate-800/50'"
        >
          <p
            class="text-[0.7rem] uppercase tracking-[0.16em]"
            :class="isNightshade ? 'text-teal-200' : 'text-amber-300'"
          >
            Status
          </p>
          <div
            class="mt-2 h-40 overflow-auto rounded border text-[0.7rem] font-mono"
            :class="isNightshade ? 'border-teal-400/20 bg-black/80 text-teal-100' : 'border-slate-600 bg-slate-800 text-slate-200'"
          >
            <div v-if="!statusLines.length" class="p-2 opacity-70">
              Waiting for a playbook run. When you start a scenario, progress will appear here.
            </div>
            <div v-else class="p-2">
              <div v-if="running" class="flex items-center gap-2 mb-2 pb-2 border-b" :class="isNightshade ? 'border-teal-400/20' : 'border-slate-600'">
                <svg class="w-4 h-4 animate-spin" :class="isNightshade ? 'text-teal-400' : 'text-amber-400'" fill="none" viewBox="0 0 24 24">
                  <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                  <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                <span :class="isNightshade ? 'text-teal-300' : 'text-amber-300'">Running scenario...</span>
              </div>
              <pre class="whitespace-pre-wrap break-words">{{ statusLines.join('\n') }}</pre>
            </div>
          </div>
        </div>

        <div class="grid gap-3 md:grid-cols-2">
          <div
            class="rounded-md border p-3"
            :class="isNightshade ? 'border-teal-400/30 bg-black/60' : 'border-amber-500/30 bg-slate-800/50'"
          >
            <p class="text-[0.7rem] uppercase tracking-[0.16em] text-[var(--np-muted-text)]">
              Scans Running
            </p>
            <p class="mt-1 text-[0.7rem]">
              <span v-if="scanIds.length > 0">
                {{ scanIds.length }} scan(s) initiated: 
                <span class="font-mono">{{ scanIds.map(id => `#${id}`).join(', ') }}</span>
              </span>
              <span v-else>
                No scans started yet for this session.
              </span>
            </p>
          </div>
          <div
            class="rounded-md border p-3"
            :class="isNightshade ? 'border-teal-400/30 bg-black/60' : 'border-amber-500/30 bg-slate-800/50'"
          >
            <p class="text-[0.7rem] uppercase tracking-[0.16em] text-[var(--np-muted-text)]">
              Progress
            </p>
            <p class="mt-1 text-[0.7rem]">
              <span v-if="totalScans > 0">
                {{ completedScans }} / {{ totalScans }} scans completed
                <span 
                  v-if="completedScans === totalScans && totalScans > 0"
                  class="ml-2 text-emerald-400"
                >Done!</span>
              </span>
              <span v-else>
                Waiting for scans to start.
              </span>
            </p>
          </div>
        </div>

        <div
          class="rounded-md border p-3"
          :class="isNightshade ? 'border-teal-400/30 bg-black/60' : 'border-amber-500/30 bg-slate-800/50'"
        >
          <p class="text-[0.7rem] uppercase tracking-[0.16em] text-[var(--np-muted-text)]">
            Safety note
          </p>
          <p class="mt-1 text-[0.7rem]" :class="isNightshade ? 'text-teal-100/80' : 'text-slate-400'">
            These playbooks can generate malformed or aggressive packets. Use them responsibly on
            networks and systems you own or are explicitly authorised to test.
          </p>
        </div>
      </div>
    </section>
  </div>
</template>