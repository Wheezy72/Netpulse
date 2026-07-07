<script setup lang="ts">
import { ref, computed, onMounted, watch } from "vue";
import axios from "axios";

const props = defineProps<{
  theme: "nightshade" | "sysadmin";
  isAdmin?: boolean;
}>();

// Offline Simulation State
const isOfflineMode = ref<boolean>(
  localStorage.getItem("np-offline-mode") === "true"
);

watch(isOfflineMode, (val) => {
  localStorage.setItem("np-offline-mode", String(val));
});

// IndexedDB Helper
const DB_NAME = "NetpulseOfflineDB";
const DB_VERSION = 1;

function getDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = (event: any) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains("devices")) {
        db.createObjectStore("devices", { keyPath: "id" });
      }
      if (!db.objectStoreNames.contains("commands")) {
        db.createObjectStore("commands", { keyPath: "id" });
      }
    };
    request.onsuccess = (event: any) => resolve(event.target.result);
    request.onerror = (event: any) => reject(event.target.error);
  });
}

// Local Cache States
const cachedDevices = ref<any[]>([]);
const cachedCommands = ref<any[]>([]);
const lastSyncTime = ref<string>(localStorage.getItem("np-last-sync") || "Never");
const syncLoading = ref(false);
const syncError = ref<string | null>(null);

// Search & MiniSearch State
const searchQuery = ref("");
const searchResults = ref<any[]>([]);

const commandQuery = ref("");
const commandResults = ref<any[]>([]);
const selectedCommand = ref<any | null>(null);
const scratchpadInput = ref("");

// Check if draft matches the regex validator
const scratchpadIsValid = computed(() => {
  if (!selectedCommand.value || !scratchpadInput.value.trim()) return null;
  try {
    const regex = new RegExp(selectedCommand.value.regex_validator, "i");
    return regex.test(scratchpadInput.value.trim());
  } catch {
    return false;
  }
});

// Preloaded hardware command database (cheatsheets)
const defaultCommands = [
  {
    id: "huawei-ospf-reset",
    vendor: "huawei",
    os: "vrp",
    protocol: "ospf",
    category: "routing",
    intent: "reset process clear adjacencies",
    syntax: "reset ospf {process_id} process",
    example: "reset ospf 1 process",
    warning: "Drops all OSPF neighbor adjacencies. Other routers must rerun SPF. Consider Graceful Restart.",
    regex_validator: "^reset\\s+ospf\\s+\\d+\\s+process$"
  },
  {
    id: "cisco-ios-interface-shutdown",
    vendor: "cisco",
    os: "ios",
    protocol: "ethernet",
    category: "interface",
    intent: "disable port admin down shutdown interface",
    syntax: "interface {interface_name} \\n shutdown",
    example: "interface GigabitEthernet1/0/12 \n shutdown",
    warning: "Administratively disables the physical port. Verify this is not an active uplink/trunk before execution.",
    regex_validator: "^interface\\s+[a-zA-Z0-9/\\.]+\\s+shutdown$"
  },
  {
    id: "cisco-ios-no-shutdown",
    vendor: "cisco",
    os: "ios",
    protocol: "ethernet",
    category: "interface",
    intent: "enable port admin up no shutdown interface",
    syntax: "interface {interface_name} \\n no shutdown",
    example: "interface GigabitEthernet1/0/12 \n no shutdown",
    warning: "Brings the interface up physically. Downstream devices will begin autonegotiation.",
    regex_validator: "^interface\\s+[a-zA-Z0-9/\\.]+\\s+no\\s+shutdown$"
  },
  {
    id: "juniper-commit",
    vendor: "juniper",
    os: "junos",
    protocol: "system",
    category: "configuration",
    intent: "commit changes apply confirm configuration",
    syntax: "commit confirmed {minutes}",
    example: "commit confirmed 5",
    warning: "Applies changes with automatic rollback if not confirmed. Crucial for remote configurations.",
    regex_validator: "^commit\\s+confirmed(\\s+\\d+)?$"
  },
  {
    id: "cisco-bgp-shutdown",
    vendor: "cisco",
    os: "ios-xr",
    protocol: "bgp",
    category: "routing",
    intent: "shutdown bgp neighbor peer isolation",
    syntax: "router bgp {asn} \\n neighbor {peer_ip} shutdown",
    example: "router bgp 65000 \n neighbor 198.51.100.2 shutdown",
    warning: "Gracefully tears down BGP peering session. Traffic will divert to redundant paths.",
    regex_validator: "^router\\s+bgp\\s+\\d+\\s+neighbor\\s+\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\s+shutdown$"
  }
];

// Regex Config Checker State
const rawConfigInput = ref("");
const showCheckerReport = ref(false);
const configScore = ref(0);
const checklistResults = ref<
  {
    id: string;
    title: string;
    description: string;
    status: "pass" | "fail";
    remediation: string;
  }[]
>([]);

// Prebuilt compliance rules for Config Checker
const complianceRules = [
  {
    id: "pw_encrypt",
    title: "Password Encryption Enabled",
    description: "Ensure service password-encryption is enabled to prevent plaintext password leakage.",
    regex: /^service password-encryption/m,
    negative: false,
    remediation: "Run command: 'service password-encryption' in global configuration mode.",
  },
  {
    id: "no_telnet",
    title: "No Telnet Permitted",
    description: "Block insecure cleartext Telnet and restrict line vty access to SSH only.",
    regex: /transport input.*telnet/i,
    negative: true,
    remediation: "Under line configuration, run: 'transport input ssh' to disable Telnet.",
  },
  {
    id: "snmp_community",
    title: "No Default SNMP Communities",
    description: "Ensure standard default read/write communities ('public', 'private') are disabled.",
    regex: /snmp-server community (public|private)/i,
    negative: true,
    remediation: "Disable defaults: 'no snmp-server community public' and specify secure custom strings.",
  },
  {
    id: "no_http",
    title: "Insecure HTTP Server Disabled",
    description: "Ensure insecure web management via HTTP is turned off.",
    regex: /^ip http server/m,
    negative: true,
    remediation: "Run command: 'no ip http server'. Enable secure access using 'ip http secure-server'.",
  },
  {
    id: "logging_buffered",
    title: "Local Buffered Logging Configured",
    description: "Ensure events are stored locally in a buffer for offline diagnostic retrievals.",
    regex: /^logging buffered/m,
    negative: false,
    remediation: "Run command: 'logging buffered 16384' to allocate internal memory for active event logging.",
  },
];

async function syncData() {
  syncLoading.value = true;
  syncError.value = null;
  try {
    const { data: devicesList } = await axios.get("/api/devices");
    const db = await getDB();
    
    // Save Devices
    const tx = db.transaction(["devices", "commands"], "readwrite");
    const devStore = tx.objectStore("devices");
    devStore.clear();
    for (const dev of devicesList) {
      devStore.put(dev);
    }
    
    // Save default commands if needed
    const cmdStore = tx.objectStore("commands");
    cmdStore.clear();
    for (const cmd of defaultCommands) {
      cmdStore.put(cmd);
    }

    const now = new Date().toLocaleString();
    lastSyncTime.value = now;
    localStorage.setItem("np-last-sync", now);
    await loadFromIndexedDB();
  } catch (err: any) {
    syncError.value = "Sync failed. Ensure server connection is active. " + (err.message || "");
  } finally {
    syncLoading.value = false;
  }
}

async function loadFromIndexedDB() {
  try {
    const db = await getDB();
    
    // Load devices
    const txDevices = db.transaction(["devices"], "readonly");
    const devStore = txDevices.objectStore("devices");
    const devRequest = devStore.getAll();
    devRequest.onsuccess = () => {
      cachedDevices.value = devRequest.result || [];
      runFuzzySearch();
    };

    // Load commands
    const txCmds = db.transaction(["commands"], "readonly");
    const cmdStore = txCmds.objectStore("commands");
    const cmdRequest = cmdStore.getAll();
    cmdRequest.onsuccess = () => {
      cachedCommands.value = cmdRequest.result || [];
      if (!cachedCommands.value.length) {
        // Hydrate from defaults if IndexedDB is empty
        cachedCommands.value = defaultCommands;
        saveDefaultCommands();
      }
      runCommandSearch();
    };
  } catch (err) {
    console.error("Failed to load local DB cache:", err);
  }
}

async function saveDefaultCommands() {
  try {
    const db = await getDB();
    const tx = db.transaction(["commands"], "readwrite");
    const store = tx.objectStore("commands");
    for (const cmd of defaultCommands) {
      store.put(cmd);
    }
  } catch (err) {
    console.error("Failed to save default commands:", err);
  }
}

function runFuzzySearch() {
  if (!searchQuery.value.trim()) {
    searchResults.value = cachedDevices.value;
    return;
  }
  const term = searchQuery.value.toLowerCase().trim();
  
  searchResults.value = cachedDevices.value
    .map((dev) => {
      let score = 0;
      const ip = (dev.ip_address || "").toLowerCase();
      const host = (dev.hostname || "").toLowerCase();
      const type = (dev.device_type || "").toLowerCase();
      const zone = (dev.zone || "").toLowerCase();

      if (ip.includes(term)) score += 10;
      if (host.includes(term)) score += 8;
      if (type.includes(term)) score += 5;
      if (zone.includes(term)) score += 3;

      return { dev, score };
    })
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score)
    .map((item) => item.dev);
}

// MiniSearch simulation for hardware syntax commands
function runCommandSearch() {
  if (!commandQuery.value.trim()) {
    commandResults.value = cachedCommands.value;
    return;
  }
  const term = commandQuery.value.toLowerCase().trim();

  // Inverted-index scoring with field boosting
  commandResults.value = cachedCommands.value
    .map((cmd) => {
      let score = 0;
      const vendor = (cmd.vendor || "").toLowerCase();
      const protocol = (cmd.protocol || "").toLowerCase();
      const intent = (cmd.intent || "").toLowerCase();
      const os = (cmd.os || "").toLowerCase();

      if (vendor === term) score += 20; // exact match boost
      else if (vendor.includes(term)) score += 10;

      if (protocol === term) score += 15;
      else if (protocol.includes(term)) score += 8;

      if (intent.includes(term)) score += 5;
      if (os.includes(term)) score += 5;

      return { cmd, score };
    })
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score)
    .map((item) => item.cmd);
}

// Topology node calculation (Offline-rendered SVG layout)
const topologyNodes = computed(() => {
  const list = cachedDevices.value;
  if (!list.length) return [];

  const width = 600;
  const height = 300;
  const centerX = width / 2;
  const centerY = height / 2;

  const nodes = list.map((dev, idx) => {
    const angle = (idx / list.length) * 2 * Math.PI;
    const radius = 100 + (idx % 2) * 25;
    return {
      id: dev.id,
      label: dev.hostname || dev.ip_address,
      ip: dev.ip_address,
      x: centerX + radius * Math.cos(angle),
      y: centerY + radius * Math.sin(angle),
      isGateway: dev.is_gateway,
      type: dev.device_type || "host"
    };
  });

  const gwNode = nodes.find(n => n.isGateway);
  if (gwNode) {
    gwNode.x = centerX;
    gwNode.y = centerY;
  }

  return nodes;
});

const topologyLinks = computed(() => {
  const nodes = topologyNodes.value;
  const gwNode = nodes.find(n => n.isGateway);
  if (!gwNode || nodes.length < 2) return [];

  return nodes
    .filter(n => !n.isGateway)
    .map(n => ({
      source: n,
      target: gwNode
    }));
});

function selectCommand(cmd: any) {
  selectedCommand.value = cmd;
  scratchpadInput.value = "";
}

function analyzeConfiguration() {
  if (!rawConfigInput.value.trim()) return;

  const results = complianceRules.map((rule) => {
    const matches = rule.regex.test(rawConfigInput.value);
    const passed = rule.negative ? !matches : matches;

    return {
      id: rule.id,
      title: rule.title,
      description: rule.description,
      status: passed ? ("pass" as const) : ("fail" as const),
      remediation: rule.remediation,
    };
  });

  const passedCount = results.filter((r) => r.status === "pass").length;
  configScore.value = Math.round((passedCount / complianceRules.length) * 100);
  checklistResults.value = results;
  showCheckerReport.value = true;
}

function loadDemoCiscoConfig() {
  rawConfigInput.value = `!
hostname Core-Switch-01
!
no service password-encryption
!
ip http server
!
snmp-server community public RO
!
logging buffered 16384
!
line vty 0 4
 transport input telnet ssh
!
end`;
}

onMounted(() => {
  loadFromIndexedDB();
});
</script>

<template>
  <div class="space-y-6">
    <!-- Offline Indicator Banner -->
    <div
      v-if="isOfflineMode"
      class="animate-pulse flex items-center justify-between p-3 rounded-xl border border-red-500/30 bg-red-500/10 text-red-400 text-xs font-mono"
    >
      <div class="flex items-center gap-2">
        <span class="w-2.5 h-2.5 rounded-full bg-red-500 animate-ping"></span>
        <span>[OFFLINE MODE ACTIVE] Operating from Local IndexedDB Cache. REST API requests bypassed.</span>
      </div>
      <button
        @click="isOfflineMode = false"
        class="px-3 py-1 rounded bg-red-500/20 border border-red-500/40 hover:bg-red-500/30 transition-all text-[10px] uppercase font-bold"
      >
        Reconnect
      </button>
    </div>
    
    <div
      v-else
      class="flex items-center justify-between p-3 rounded-xl border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 text-xs font-mono"
    >
      <div class="flex items-center gap-2">
        <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
        <span>Backup Friend Online. Database baseline is synchronized with the server cache.</span>
      </div>
      <button
        @click="isOfflineMode = true"
        class="px-3 py-1 rounded bg-emerald-500/20 border border-emerald-500/40 hover:bg-emerald-500/30 transition-all text-[10px] uppercase font-bold"
      >
        Simulate Offline
      </button>
    </div>

    <!-- Header Section -->
    <div class="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
      <div>
        <h2 class="text-xl font-bold uppercase tracking-wider text-[var(--np-text)] font-sans">
          Backup Friend Assistant
        </h2>
        <p class="text-xs text-[var(--np-text-dim)]">
          Local IndexedDB caching, client-side MiniSearch cheatsheets, offline SVG topology map, and CLI validation console.
        </p>
      </div>

      <div class="flex items-center gap-3">
        <div class="text-right text-[10px] font-mono text-[var(--np-text-dim)]">
          <div>Last Synchronized: <span class="text-[var(--np-text)] font-bold">{{ lastSyncTime }}</span></div>
        </div>
        <button
          @click="syncData"
          :disabled="syncLoading || isOfflineMode"
          class="np-cyber-btn flex items-center gap-1.5 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <svg
            v-if="syncLoading"
            class="w-3.5 h-3.5 animate-spin"
            fill="none"
            viewBox="0 0 24 24"
          >
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
          </svg>
          <span>Sync Now</span>
        </button>
      </div>
    </div>

    <div v-if="syncError" class="p-3 border border-red-500/20 bg-red-500/5 text-xs text-red-400 rounded-lg">
      {{ syncError }}
    </div>

    <!-- Main Workspace Grid -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      
      <!-- MiniSearch Hardware Cheatsheets -->
      <div class="np-panel p-4 flex flex-col min-h-[400px]">
        <header class="np-panel-header -mx-4 -mt-4 mb-4 px-4">
          <div class="flex flex-col">
            <span class="np-panel-title">MiniSearch Command Guides</span>
            <span class="text-[0.65rem] text-[var(--np-text-dim)]">
              Perform instantaneous, local queries of CLI syntax and OSPF/BGP disaster recovery baselines.
            </span>
          </div>
        </header>

        <div class="mb-3">
          <input
            v-model="commandQuery"
            @input="runCommandSearch"
            type="text"
            placeholder="Search vendor, protocol or intent (e.g. huawei reset ospf)..."
            class="np-neon-input w-full px-3 py-2 text-xs font-mono"
          />
        </div>

        <div class="flex-1 overflow-y-auto custom-scrollbar max-h-[300px] border border-[var(--np-border-subtle)] rounded-lg divide-y divide-[var(--np-border-subtle)]">
          <div
            v-for="cmd in commandResults"
            :key="cmd.id"
            @click="selectCommand(cmd)"
            class="p-3 hover:bg-white/[0.02] cursor-pointer transition-colors space-y-1"
            :class="{ 'bg-purple-500/5 border-l-2 border-purple-500': selectedCommand?.id === cmd.id }"
          >
            <div class="flex justify-between items-center text-[10px]">
              <span class="font-bold text-purple-400 uppercase tracking-widest">{{ cmd.vendor }} ({{ cmd.os }})</span>
              <span class="px-1.5 py-0.2 rounded bg-black/40 text-[9px] font-mono text-zinc-400">{{ cmd.protocol }}</span>
            </div>
            <div class="text-xs text-[var(--np-text)] font-semibold">{{ cmd.intent }}</div>
            <div class="text-[10px] font-mono text-zinc-500">{{ cmd.syntax }}</div>
          </div>
        </div>
      </div>

      <!-- Command Details & Interactive Regex Scratchpad -->
      <div class="np-panel p-4 flex flex-col min-h-[400px]">
        <header class="np-panel-header -mx-4 -mt-4 mb-4 px-4">
          <div class="flex flex-col">
            <span class="np-panel-title">Interactive Syntax Scratchpad</span>
            <span class="text-[0.65rem] text-[var(--np-text-dim)]">
              Draft switch/router command scripts and validate syntax rules deterministically in real-time.
            </span>
          </div>
        </header>

        <div v-if="selectedCommand" class="flex-1 flex flex-col gap-4">
          <div class="space-y-2 border-b border-[var(--np-border-subtle)] pb-3">
            <div class="flex justify-between items-center">
              <span class="text-xs font-bold text-white">{{ selectedCommand.intent }}</span>
              <span class="text-[9px] uppercase tracking-widest text-zinc-400">Rules Engine Active</span>
            </div>
            <div class="text-[10px] leading-relaxed text-yellow-400/90 bg-yellow-400/5 border border-yellow-400/20 p-2.5 rounded-lg">
              <span class="font-bold block mb-0.5">⚠️ WARNING:</span>
              {{ selectedCommand.warning }}
            </div>
            <div class="text-xs pt-1.5">
              <div class="text-[10px] text-zinc-500 font-mono">Syntax:</div>
              <code class="font-mono text-purple-300 block bg-black/30 p-2 rounded text-[10px] whitespace-pre-line">{{ selectedCommand.syntax }}</code>
            </div>
            <div class="text-xs pt-1">
              <div class="text-[10px] text-zinc-500 font-mono">Example:</div>
              <code class="font-mono text-emerald-400 block bg-black/30 p-2 rounded text-[10px] whitespace-pre-line">{{ selectedCommand.example }}</code>
            </div>
          </div>

          <div class="flex-1 flex flex-col gap-2 mt-auto">
            <span class="text-[10px] font-mono text-zinc-400">Draft Command Scratchpad:</span>
            <textarea
              v-model="scratchpadInput"
              rows="3"
              placeholder="Type command exactly (e.g. reset ospf 1 process)"
              class="np-neon-input w-full p-2.5 font-mono text-[11px]"
            ></textarea>
            
            <div class="flex justify-between items-center mt-1">
              <span class="text-[9px] text-zinc-500 font-mono">Validation Regex: {{ selectedCommand.regex_validator }}</span>
              <span
                v-if="scratchpadIsValid !== null"
                class="px-2 py-0.5 rounded text-[9px] font-mono uppercase tracking-widest"
                :class="[
                  scratchpadIsValid
                    ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-400'
                    : 'bg-red-500/10 border border-red-500/30 text-red-400'
                ]"
              >
                {{ scratchpadIsValid ? "PASS (VALID)" : "FAIL (INVALID)" }}
              </span>
            </div>
          </div>
        </div>

        <div v-else class="flex-1 flex items-center justify-center text-xs text-[var(--np-text-dim)] font-mono">
          Select a command guide from the left panel to begin syntax verification.
        </div>
      </div>

    </div>

    <!-- Offline Inventory & Topology Map Grid -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      
      <!-- Local Inventory & Client-Side Fuzzy Search -->
      <div class="np-panel p-4 flex flex-col min-h-[380px]">
        <header class="np-panel-header -mx-4 -mt-4 mb-4 px-4">
          <div class="flex flex-col">
            <span class="np-panel-title">IndexedDB Device Inventory</span>
            <span class="text-[0.65rem] text-[var(--np-text-dim)]">
              Queried completely within the browser sandbox using client-side fuzzy scores.
            </span>
          </div>
        </header>

        <div class="mb-4">
          <input
            v-model="searchQuery"
            @input="runFuzzySearch"
            type="text"
            placeholder="Fuzzy search hosts, IPs, or zones..."
            class="np-neon-input w-full px-3 py-2 text-xs font-mono"
          />
        </div>

        <div class="flex-1 overflow-y-auto custom-scrollbar max-h-[250px] border border-[var(--np-border-subtle)] rounded-lg">
          <table class="w-full text-left border-collapse text-xs">
            <thead>
              <tr class="bg-[var(--np-thead-bg)] text-[0.6rem] text-[var(--np-text-dim)] uppercase tracking-wider border-b border-[var(--np-border-subtle)]">
                <th class="py-2.5 px-3">IP Address</th>
                <th class="py-2.5 px-3">Hostname</th>
                <th class="py-2.5 px-3">Zone</th>
                <th class="py-2.5 px-3">Type</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-[var(--np-border-subtle)]">
              <tr v-for="dev in searchResults" :key="dev.id" class="hover:bg-white/[0.02] transition-colors">
                <td class="py-2 px-3 font-mono text-[var(--np-text)] font-semibold">{{ dev.ip_address }}</td>
                <td class="py-2 px-3 text-[var(--np-text-dim)]">{{ dev.hostname || "—" }}</td>
                <td class="py-2 px-3 text-[var(--np-text-muted)]">{{ dev.zone || "—" }}</td>
                <td class="py-2 px-3">
                  <span class="sp-badge">{{ dev.device_type || "Unknown" }}</span>
                </td>
              </tr>
              <tr v-if="searchResults.length === 0">
                <td colspan="4" class="py-6 text-center text-xs text-[var(--np-text-dim)] font-mono">
                  No synced records match query. Run Sync while online.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Offline D3-style SVG Topology visualization -->
      <div class="np-panel p-4 flex flex-col min-h-[380px]">
        <header class="np-panel-header -mx-4 -mt-4 mb-4 px-4">
          <div class="flex flex-col">
            <span class="np-panel-title">Offline Network Topology</span>
            <span class="text-[0.65rem] text-[var(--np-text-dim)]">
              Interactive radial topology map rendered entirely client-side using SVG vectors.
            </span>
          </div>
        </header>

        <div class="flex-1 flex items-center justify-center border border-[var(--np-border-subtle)] rounded-lg bg-black/30 overflow-hidden relative min-h-[250px]">
          <svg v-if="topologyNodes.length > 0" class="w-full h-full" viewBox="0 0 600 300">
            <!-- Draw link connections -->
            <line
              v-for="(link, idx) in topologyLinks"
              :key="idx"
              :x1="link.source.x"
              :y1="link.source.y"
              :x2="link.target.x"
              :y2="link.target.y"
              stroke="rgba(168, 85, 247, 0.4)"
              stroke-width="1.5"
              stroke-dasharray="4"
            />

            <!-- Draw device nodes -->
            <g v-for="node in topologyNodes" :key="node.id">
              <circle
                :cx="node.x"
                :cy="node.y"
                :r="node.isGateway ? 14 : 9"
                :fill="node.isGateway ? '#10b981' : node.type === 'switch' ? '#3b82f6' : '#a855f7'"
                class="transition-all hover:scale-125 cursor-pointer filter drop-shadow-[0_0_6px_rgba(168,85,247,0.5)]"
              />
              <text
                :x="node.x"
                :y="node.y - (node.isGateway ? 18 : 13)"
                fill="#cbd5e1"
                font-size="9"
                font-family="monospace"
                text-anchor="middle"
                class="pointer-events-none select-none font-bold"
              >
                {{ node.label }}
              </text>
            </g>
          </svg>

          <div v-else class="text-xs text-[var(--np-text-dim)] font-mono">
            No devices cached. Synchronize baseline data to render topology.
          </div>
        </div>
      </div>

    </div>

    <!-- Configuration Hardening Analyzer -->
    <div class="np-panel p-4 flex flex-col min-h-[380px]">
      <header class="np-panel-header -mx-4 -mt-4 mb-4 px-4">
        <div class="flex flex-col">
          <span class="np-panel-title">Configuration Hardening Analyzer</span>
          <span class="text-[0.65rem] text-[var(--np-text-dim)]">
            Paste switch/router running configurations to audit compliance using local regex definitions.
          </span>
        </div>
      </header>

      <div class="flex-1 flex flex-col gap-4">
        <div class="flex justify-between items-center text-[10px] font-mono text-[var(--np-text-dim)]">
          <span>Paste running config:</span>
          <button @click="loadDemoCiscoConfig" class="text-purple-400 hover:text-purple-300 underline">
            Load Default Compliance Baseline
          </button>
        </div>

        <textarea
          v-model="rawConfigInput"
          rows="6"
          placeholder="! Cisco IOS configuration baseline..."
          class="np-neon-input w-full p-3 font-mono text-[10px] leading-relaxed resize-none bg-black/40 flex-1"
        ></textarea>

        <button @click="analyzeConfiguration" class="w-full py-2.5 np-login-btn font-bold text-xs uppercase">
          Analyze Config Compliance
        </button>
      </div>
    </div>

    <!-- Checker Audit Report -->
    <div v-if="showCheckerReport" class="np-panel p-5 mt-6 animate-fade-in border border-purple-500/25">
      <header class="flex items-center justify-between border-b border-[var(--np-border-subtle)] pb-3 mb-4">
        <div>
          <span class="text-xs font-bold uppercase tracking-wider text-purple-400">Compliance Audit Report</span>
          <p class="text-[10px] text-[var(--np-text-dim)]">Evaluated locally via sandboxed regex rules.</p>
        </div>

        <div class="flex items-center gap-3">
          <span class="text-[10px] font-mono text-[var(--np-text-dim)]">Overall Score:</span>
          <span
            class="text-lg font-bold font-mono px-3 py-1 rounded-lg border"
            :class="[
              configScore >= 80 ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' :
              configScore >= 50 ? 'bg-amber-500/10 border-amber-500/30 text-amber-400' :
              'bg-red-500/10 border-red-500/30 text-red-400'
            ]"
          >
            {{ configScore }}%
          </span>
        </div>
      </header>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div
          v-for="rule in checklistResults"
          :key="rule.id"
          class="p-4 rounded-xl border flex gap-3 transition-all hover:bg-white/[0.01]"
          :class="[
            rule.status === 'pass'
              ? 'border-emerald-500/20 bg-emerald-500/5'
              : 'border-red-500/20 bg-red-500/5'
          ]"
        >
          <div class="text-lg shrink-0 mt-0.5">
            {{ rule.status === "pass" ? "🟢" : "🔴" }}
          </div>
          <div class="space-y-1 text-xs">
            <div class="font-bold text-[var(--np-text)] flex items-center gap-2">
              <span>{{ rule.title }}</span>
              <span
                class="text-[9px] px-1.5 py-0.2 rounded font-mono uppercase tracking-widest border shrink-0"
                :class="[
                  rule.status === 'pass'
                    ? 'border-emerald-500/20 text-emerald-400 bg-emerald-500/10'
                    : 'border-red-500/20 text-red-400 bg-red-500/10'
                ]"
              >
                {{ rule.status }}
              </span>
            </div>
            <p class="text-[10px] text-[var(--np-text-dim)]">{{ rule.description }}</p>
            <div v-if="rule.status === 'fail'" class="text-[10px] pt-1.5 border-t border-[var(--np-border-subtle)] text-[var(--np-text-muted)]">
              <span class="font-bold text-rose-400 uppercase tracking-widest text-[9px] block mb-0.5">Remediation:</span>
              <code class="font-mono text-zinc-300 bg-black/40 px-1 py-0.5 rounded">{{ rule.remediation }}</code>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.animate-fade-in {
  animation: fadeIn 0.4s cubic-bezier(0.25, 0.8, 0.25, 1) forwards;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: translateY(0); }
}
</style>
