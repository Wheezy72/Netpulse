<script setup lang="ts">
import axios from "axios";
import { computed, onMounted, ref } from "vue";

type Theme = "nightshade" | "sysadmin";

interface Props {
  theme: Theme;
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

interface Preset {
  id: string;
  name: string;
  command: string;
  description: string;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  (e: "toast", type: "success" | "error" | "warning" | "info", message: string): void;
}>();
const isNightshade = computed(() => props.theme === "nightshade");

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

async function loadPresets(): Promise<void> {
  try {
    const { data } = await axios.get<Preset[]>("/api/nmap/presets");
    presets.value = data;
  } catch {
    // Non-fatal
  }
}

async function loadHistory(): Promise<void> {
  try {
    const { data } = await axios.get<ScanResult[]>("/api/nmap/history");
    scanHistory.value = data;
  } catch {
    // Non-fatal
  }
}

function selectPreset(preset: Preset): void {
  command.value = preset.command;
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
          
          if (result.status === "completed") {
            emit("toast", "success", `Scan completed: ${result.scan_type} on ${result.target}`);
          } else if (result.status === "error") {
            emit("toast", "error", `Scan failed: ${result.target}`);
          } else if (result.status === "timeout") {
            emit("toast", "warning", `Scan timed out: ${result.target}`);
          }
        }
      } catch {
        // Continue polling
      }
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

onMounted(() => {
  loadPresets();
  loadHistory();
});
</script>

<template>
  <main
    class="min-h-screen space-y-4 p-4"
    :class="isNightshade ? 'bg-black/95 text-teal-100' : 'bg-slate-900 text-slate-100'"
  >
    <header class="flex items-center justify-between">
      <div>
        <h1
          class="text-xl font-bold tracking-wide"
          :class="isNightshade ? 'text-teal-300' : 'text-amber-400'"
        >
          Nmap Scanner
        </h1>
        <p class="text-xs" :class="isNightshade ? 'text-teal-100/60' : 'text-slate-400'">
          Network reconnaissance with AI-powered command generation
        </p>
      </div>
    </header>

    <div class="grid gap-4 lg:grid-cols-2">
      <section
        class="rounded-lg border p-4 space-y-4"
        :class="isNightshade ? 'border-teal-400/30 bg-black/60' : 'border-slate-700 bg-slate-800/50'"
      >
        <h2
          class="text-sm font-semibold uppercase tracking-wider"
          :class="isNightshade ? 'text-teal-200' : 'text-amber-300'"
        >
          AI Command Generator
        </h2>
        
        <div class="space-y-3">
          <div>
            <label class="text-xs text-slate-400">Target IP/Hostname</label>
            <input
              v-model="target"
              type="text"
              placeholder="192.168.1.1 or example.com"
              class="mt-1 w-full rounded-md border px-3 py-2 text-sm"
              :class="isNightshade
                ? 'border-teal-400/30 bg-black/50 text-teal-100 placeholder-teal-100/40'
                : 'border-slate-600 bg-slate-900 text-slate-100 placeholder-slate-500'"
            />
          </div>
          
          <div>
            <label class="text-xs text-slate-400">Describe what you want to scan</label>
            <textarea
              v-model="aiDescription"
              rows="2"
              placeholder="e.g., Scan for vulnerabilities using UDP, don't cause noise"
              class="mt-1 w-full rounded-md border px-3 py-2 text-sm resize-none"
              :class="isNightshade
                ? 'border-teal-400/30 bg-black/50 text-teal-100 placeholder-teal-100/40'
                : 'border-slate-600 bg-slate-900 text-slate-100 placeholder-slate-500'"
            ></textarea>
          </div>
          
          <button
            @click="generateAICommand"
            :disabled="aiLoading"
            class="w-full rounded-md border px-4 py-2 text-sm font-medium transition-colors"
            :class="isNightshade
              ? 'border-purple-400/50 bg-purple-500/20 text-purple-300 hover:bg-purple-500/30'
              : 'border-amber-500/50 bg-amber-500/20 text-amber-300 hover:bg-amber-500/30'"
          >
            {{ aiLoading ? "Generating..." : "Generate Command with AI" }}
          </button>
          
          <div v-if="aiExplanation" class="rounded-md border p-3 text-xs"
               :class="isNightshade ? 'border-purple-400/30 bg-purple-500/10 text-purple-200' : 'border-amber-500/30 bg-amber-500/10 text-amber-200'">
            <pre class="whitespace-pre-wrap font-mono">{{ aiExplanation }}</pre>
          </div>
        </div>

        <hr :class="isNightshade ? 'border-teal-400/20' : 'border-slate-700'" />
        
        <div>
          <label class="text-xs text-slate-400">Presets</label>
          <div class="mt-2 flex flex-wrap gap-2">
            <button
              v-for="preset in presets"
              :key="preset.id"
              @click="selectPreset(preset)"
              class="rounded-md border px-2 py-1 text-xs transition-colors"
              :class="isNightshade
                ? 'border-teal-400/30 bg-black/30 text-teal-200 hover:bg-teal-500/20'
                : 'border-slate-600 bg-slate-700/50 text-slate-300 hover:bg-slate-700'"
              :title="preset.description"
            >
              {{ preset.name }}
            </button>
          </div>
        </div>

        <div>
          <label class="text-xs text-slate-400">Command</label>
          <input
            v-model="command"
            type="text"
            class="mt-1 w-full rounded-md border px-3 py-2 font-mono text-sm"
            :class="isNightshade
              ? 'border-teal-400/30 bg-black/50 text-teal-100'
              : 'border-slate-600 bg-slate-900 text-slate-100'"
          />
        </div>

        <div class="flex items-center gap-3">
          <label class="flex items-center gap-2 text-xs">
            <input
              v-model="saveResults"
              type="checkbox"
              class="rounded"
            />
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
              : 'bg-amber-600 text-white hover:bg-amber-500'"
        >
          <svg v-if="loading" class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          {{ loading ? "Scanning..." : "Execute Scan" }}
        </button>

        <p v-if="error" class="text-xs text-rose-400">{{ error }}</p>
      </section>

      <section
        class="rounded-lg border p-4 space-y-3"
        :class="isNightshade ? 'border-teal-400/30 bg-black/60' : 'border-slate-700 bg-slate-800/50'"
      >
        <div class="flex items-center justify-between">
          <h2
            class="text-sm font-semibold uppercase tracking-wider"
            :class="isNightshade ? 'text-teal-200' : 'text-amber-300'"
          >
            Scan Results
          </h2>
          <button
            v-if="currentScan?.output"
            @click="downloadScanPDF"
            class="rounded-md border px-3 py-1 text-xs transition-colors"
            :class="isNightshade
              ? 'border-teal-400/30 text-teal-200 hover:bg-teal-500/20'
              : 'border-amber-500/30 text-amber-300 hover:bg-amber-500/20'"
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
                'bg-emerald-500/20 text-emerald-400': currentScan.status === 'completed',
                'bg-rose-500/20 text-rose-400': currentScan.status === 'error' || currentScan.status === 'timeout',
              }"
            >
              {{ currentScan.status.toUpperCase() }}
            </span>
            <span class="text-slate-400">{{ currentScan.scan_type }}</span>
            <span class="text-slate-500">{{ currentScan.target }}</span>
          </div>
          
          <div
            class="max-h-[400px] overflow-auto rounded-md border p-3 font-mono text-xs"
            :class="isNightshade ? 'border-teal-400/20 bg-black/80' : 'border-slate-700 bg-slate-900'"
          >
            <pre v-if="currentScan.output" class="whitespace-pre-wrap">{{ currentScan.output }}</pre>
            <div v-else class="flex flex-col items-center justify-center py-8 gap-3">
              <svg class="w-8 h-8 animate-spin" :class="isNightshade ? 'text-teal-400' : 'text-amber-400'" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              <span :class="isNightshade ? 'text-teal-100/60' : 'text-slate-400'">Scanning in progress...</span>
              <span class="text-xs text-slate-500">This may take a few minutes depending on scan type</span>
            </div>
          </div>
        </div>

        <div v-else class="py-8 text-center text-sm text-slate-500">
          Configure and execute a scan to see results
        </div>
      </section>
    </div>

    <section
      class="rounded-lg border p-4"
      :class="isNightshade ? 'border-teal-400/30 bg-black/60' : 'border-slate-700 bg-slate-800/50'"
    >
      <h2
        class="mb-3 text-sm font-semibold uppercase tracking-wider"
        :class="isNightshade ? 'text-teal-200' : 'text-amber-300'"
      >
        Scan History
      </h2>
      
      <div v-if="scanHistory.length" class="space-y-2 max-h-48 overflow-auto">
        <div
          v-for="scan in scanHistory"
          :key="scan.id"
          @click="currentScan = scan"
          class="flex items-center justify-between rounded-md border p-2 cursor-pointer transition-colors"
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
            <span class="text-xs font-medium">{{ scan.scan_type }}</span>
            <span class="text-xs text-slate-500">{{ scan.target }}</span>
          </div>
          <span class="text-xs text-slate-500">{{ formatTime(scan.started_at) }}</span>
        </div>
      </div>
      
      <div v-else class="py-4 text-center text-sm text-slate-500">
        No scans yet
      </div>
    </section>
  </main>
</template>
