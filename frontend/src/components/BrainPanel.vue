<script setup lang="ts">
import axios from "axios";
import { onBeforeUnmount, ref, computed } from "vue";

type BrainTab = "console" | "scripts";

const activeTab = ref<BrainTab>("console");
const brainLogs = ref<string[]>([]);
let logSocket: WebSocket | null = null;

const isRunningAction = ref(false);
const actionStatus = ref<string | null>(null);
const selectedTarget = ref("");

function attachLogStream(jobId: number): void {
  const token = window.localStorage.getItem("np-token");
  if (!token) {
    brainLogs.value.push("[log] No auth token available for log stream.");
    return;
  }

  if (logSocket) {
    logSocket.close();
    logSocket = null;
  }

  const apiBase =
    (import.meta as any).env?.VITE_API_BASE_URL || window.location.origin;
  const wsBase = apiBase.replace(/^http/, "ws");
  const url = `${wsBase}/api/ws/scripts/${jobId}?token=${encodeURIComponent(token)}`;

  try {
    const socket = new WebSocket(url);
    logSocket = socket;
    brainLogs.value.push(`[log] Attached to job #${jobId}`);

    socket.onmessage = (event: MessageEvent) => {
      try {
        const payload = JSON.parse(event.data as string);
        if (payload.event === "log") {
          brainLogs.value.push(payload.message);
        } else if (payload.event === "complete") {
          brainLogs.value.push(
            `[log] Job completed with status: ${payload.status}`
          );
        } else if (payload.event === "error") {
          brainLogs.value.push(`[error] ${payload.message}`);
        }
      } catch {
        brainLogs.value.push("[error] Failed to parse log message.");
      }
    };

    socket.onclose = () => {
      if (logSocket === socket) {
        logSocket = null;
      }
    };
  } catch {
    brainLogs.value.push("[error] Could not open log WebSocket.");
  }
}

async function runPrebuiltScript(
  scriptName: string,
  params: Record<string, unknown> = {}
): Promise<void> {
  isRunningAction.value = true;
  actionStatus.value = null;

  try {
    const payload = {
      script_name: scriptName,
      params,
    };
    const { data } = await axios.post<{ job_id: number }>(
      "/api/scripts/prebuilt/run",
      payload
    );
    const jobId = data.job_id;
    actionStatus.value = `Script queued (job #${jobId}).`;
    activeTab.value = "console";
    attachLogStream(jobId);
  } catch {
    actionStatus.value = "Failed to queue script.";
  } finally {
    isRunningAction.value = false;
  }
}

function clearConsole(): void {
  brainLogs.value = [];
}

async function runWanHealthReport(): Promise<void> {
  await runPrebuiltScript("wan_health_report.py");
}

async function runNewDeviceReport(): Promise<void> {
  await runPrebuiltScript("new_device_report.py");
}

async function runNmapWebRecon(): Promise<void> {
  const target = selectedTarget.value.trim();
  if (!target) {
    actionStatus.value = "Enter a target first.";
    return;
  }
  await runPrebuiltScript("nmap_web_recon.py", { target });
}

async function runNmapSmbAudit(): Promise<void> {
  const target = selectedTarget.value.trim();
  if (!target) {
    actionStatus.value = "Enter a target first.";
    return;
  }
  await runPrebuiltScript("nmap_smb_audit.py", { target });
}

onBeforeUnmount(() => {
  if (logSocket) {
    logSocket.close();
    logSocket = null;
  }
});
</script>

<template>
  <section class="np-panel p-4 np-fade-in">
    <header class="np-panel-header mb-3">
      <div class="flex flex-col">
        <span class="np-panel-title">Automation Hub</span>
        <span class="text-[0.65rem] text-[var(--np-muted-text)]">Scripts & Code Generator</span>
      </div>
    </header>

    <div class="flex gap-1 mb-3 border-b" style="border-color: var(--np-border)">
      <button
        v-for="tab in (['console', 'scripts'] as const)"
        :key="tab"
        type="button"
        @click="activeTab = tab"
        class="px-3 py-2 text-xs font-medium transition-all duration-300 border-b-2 -mb-px"
        :class="[
          activeTab === tab
            ? 'border-[var(--np-accent-primary)] text-[var(--np-accent-primary)]'
            : 'border-transparent text-[var(--np-muted-text)] hover:text-[var(--np-text)]'
        ]"
      >
        {{ tab === 'console' ? 'Console' : 'Quick Scripts' }}
      </button>
    </div>

    <div v-if="activeTab === 'console'" class="np-fade-in">
      <div
        id="brain-terminal"
        class="relative h-48 rounded-lg border bg-black/90 overflow-auto"
        style="border-color: var(--np-border)"
      >
        <div
          v-if="brainLogs.length === 0"
          class="absolute inset-0 flex flex-col items-center justify-center text-xs text-[var(--np-muted-text)] gap-2"
        >
          <svg class="w-8 h-8 opacity-30" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
          </svg>
          <span>Script output will appear here</span>
          <span class="text-[0.6rem] opacity-60">Run a quick script below</span>
        </div>
        <pre
          v-else
          class="h-full w-full whitespace-pre-wrap break-words bg-transparent p-3 text-xs font-mono text-[var(--np-text)]"
        >{{ brainLogs.join('\n') }}</pre>
      </div>
      <div class="mt-2 flex justify-end">
        <button
          v-if="brainLogs.length > 0"
          type="button"
          @click="clearConsole"
          class="text-[0.6rem] text-[var(--np-muted-text)] hover:text-[var(--np-text)] transition-colors"
        >
          Clear Console
        </button>
      </div>
    </div>

    <div v-else-if="activeTab === 'scripts'" class="np-fade-in">
      <div class="mb-3">
        <label class="text-xs text-[var(--np-muted-text)] block mb-1">Target (for network scripts)</label>
        <input
          v-model="selectedTarget"
          type="text"
          class="np-neon-input w-full rounded-lg px-3 py-2 text-sm"
          placeholder="192.168.1.0/24"
        />
      </div>

      <div class="grid grid-cols-2 md:grid-cols-4 gap-2">
        <button
          type="button"
          @click="runWanHealthReport"
          class="np-cyber-btn rounded-lg px-3 py-2.5 text-[0.7rem] disabled:opacity-50 flex flex-col items-center gap-1"
          :disabled="isRunningAction"
        >
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
          </svg>
          WAN Health
        </button>
        <button
          type="button"
          @click="runNewDeviceReport"
          class="np-cyber-btn rounded-lg px-3 py-2.5 text-[0.7rem] disabled:opacity-50 flex flex-col items-center gap-1"
          :disabled="isRunningAction"
        >
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2z" />
          </svg>
          New Devices
        </button>
        <button
          type="button"
          @click="runNmapWebRecon"
          class="np-cyber-btn rounded-lg px-3 py-2.5 text-[0.7rem] disabled:opacity-50 flex flex-col items-center gap-1"
          :disabled="isRunningAction"
        >
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9" />
          </svg>
          Web Recon
        </button>
        <button
          type="button"
          @click="runNmapSmbAudit"
          class="np-cyber-btn rounded-lg px-3 py-2.5 text-[0.7rem] disabled:opacity-50 flex flex-col items-center gap-1"
          :disabled="isRunningAction"
        >
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
          </svg>
          SMB Audit
        </button>
      </div>

      <p v-if="actionStatus" class="mt-2 text-[0.65rem] text-[var(--np-muted-text)]">
        {{ actionStatus }}
      </p>
    </div>
  </section>
</template>
