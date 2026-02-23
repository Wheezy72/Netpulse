<script setup lang="ts">
import axios from "axios";
import { computed, onMounted, ref, watch } from "vue";
import ToggleSwitch from "../components/ToggleSwitch.vue";

type Theme = "nightshade" | "sysadmin";
type InfoMode = "full" | "compact";

interface Props {
  theme: Theme;
  infoMode: InfoMode;
}


interface NetworkSegment {
  id?: number;
  name: string;
  cidr: string;
  description: string | null;
  vlan_id: number | null;
  is_active: boolean;
  scan_enabled: boolean;
}

interface NotificationSettings {
  email_enabled: boolean;
  email_address: string;
  whatsapp_enabled: boolean;
  whatsapp_number: string;
  alert_on_critical: boolean;
  alert_on_warning: boolean;
  alert_on_device_down: boolean;
  daily_digest: boolean;
}

interface AISettings {
  provider: string;
  api_key_configured: boolean;
  model: string;
  enabled: boolean;
  custom_base_url: string;
  custom_model: string;
}

const props = defineProps<Props>();

const emit = defineEmits<{
  (e: "update:infoMode", value: InfoMode): void;
}>();

const localInfoMode = ref<InfoMode>(props.infoMode);

watch(() => props.infoMode, (val) => {
  localInfoMode.value = val;
});

function setInfoMode(mode: InfoMode): void {
  localInfoMode.value = mode;
  emit("update:infoMode", mode);
}

const segments = ref<NetworkSegment[]>([]);
const segmentsLoading = ref(false);
const segmentsError = ref<string | null>(null);
const showAddSegment = ref(false);
const newSegment = ref<NetworkSegment>({
  name: "",
  cidr: "",
  description: null,
  vlan_id: null,
  is_active: true,
  scan_enabled: true,
});

const notifications = ref<NotificationSettings>({
  email_enabled: false,
  email_address: "",
  whatsapp_enabled: false,
  whatsapp_number: "",
  alert_on_critical: true,
  alert_on_warning: false,
  alert_on_device_down: true,
  daily_digest: false,
});
const notificationsSaving = ref(false);
const notificationsMessage = ref<string | null>(null);

const aiSettings = ref<AISettings>({
  provider: "openai",
  api_key_configured: false,
  model: "gpt-4o-mini",
  enabled: false,
  custom_base_url: "",
  custom_model: "",
});
const aiSaving = ref(false);
const aiMessage = ref<string | null>(null);

interface ThreatIntelSettings {
  abuseipdb_enabled: boolean;
  abuseipdb_api_key_configured: boolean;
  abuseipdb_max_age: number;
}

const threatIntel = ref<ThreatIntelSettings>({
  abuseipdb_enabled: false,
  abuseipdb_api_key_configured: false,
  abuseipdb_max_age: 90,
});
const threatIntelSaving = ref(false);
const threatIntelMessage = ref<string | null>(null);

interface ScanScheduleSettings {
  enabled: boolean;
  frequency: string;
  time: string;
  scan_type: string;
  segments: number[];
  notify_on_complete: boolean;
}

interface ScheduleOption {
  value: string;
  label: string;
  description?: string;
}

const scanSchedule = ref<ScanScheduleSettings>({
  enabled: false,
  frequency: "daily",
  time: "02:00",
  scan_type: "quick",
  segments: [],
  notify_on_complete: true,
});
const scanScheduleSaving = ref(false);
const scanScheduleMessage = ref<string | null>(null);
const frequencyOptions = ref<ScheduleOption[]>([
  { value: "hourly", label: "Hourly", description: "Run every hour" },
  { value: "daily", label: "Daily", description: "Run once per day" },
  { value: "weekly", label: "Weekly", description: "Run once per week" },
  { value: "monthly", label: "Monthly", description: "Run once per month" },
]);
const scanTypeOptions = ref<ScheduleOption[]>([
  { value: "quick", label: "Quick Scan", description: "Fast ping sweep" },
  { value: "full", label: "Full Scan", description: "Comprehensive port scan" },
  { value: "vuln", label: "Vulnerability Scan", description: "Security vulnerability detection" },
  { value: "service", label: "Service Detection", description: "Identify running services" },
]);

async function loadNetworkSegments(): Promise<void> {
  segmentsLoading.value = true;
  segmentsError.value = null;
  try {
    const { data } = await axios.get<NetworkSegment[]>("/api/network-segments");
    segments.value = data;
  } catch {
    segmentsError.value = "Failed to load network segments.";
  } finally {
    segmentsLoading.value = false;
  }
}

async function addNetworkSegment(): Promise<void> {
  if (!newSegment.value.name || !newSegment.value.cidr) return;
  
  try {
    await axios.post("/api/network-segments", newSegment.value);
    newSegment.value = {
      name: "",
      cidr: "",
      description: null,
      vlan_id: null,
      is_active: true,
      scan_enabled: true,
    };
    showAddSegment.value = false;
    await loadNetworkSegments();
  } catch {
    segmentsError.value = "Failed to add network segment.";
  }
}

async function toggleSegmentScan(segment: NetworkSegment): Promise<void> {
  if (!segment.id) return;
  try {
    await axios.put(`/api/network-segments/${segment.id}`, {
      scan_enabled: !segment.scan_enabled,
    });
    await loadNetworkSegments();
  } catch {
    segmentsError.value = "Failed to update segment.";
  }
}

async function deleteSegment(segment: NetworkSegment): Promise<void> {
  if (!segment.id) return;
  try {
    await axios.delete(`/api/network-segments/${segment.id}`);
    await loadNetworkSegments();
  } catch {
    segmentsError.value = "Failed to delete segment.";
  }
}

async function loadNotificationSettings(): Promise<void> {
  try {
    const { data } = await axios.get<NotificationSettings>("/api/settings/notifications");
    notifications.value = { ...notifications.value, ...data };
  } catch {
    // Use defaults if not configured yet
  }
}

async function saveNotificationSettings(): Promise<void> {
  notificationsSaving.value = true;
  notificationsMessage.value = null;
  try {
    await axios.put("/api/settings/notifications", notifications.value);
    notificationsMessage.value = "Notification settings saved successfully.";
    setTimeout(() => { notificationsMessage.value = null; }, 3000);
  } catch {
    notificationsMessage.value = "Failed to save notification settings.";
  } finally {
    notificationsSaving.value = false;
  }
}

async function loadAISettings(): Promise<void> {
  try {
    const { data } = await axios.get("/api/settings/ai");
    aiSettings.value = { ...aiSettings.value, ...data };
  } catch {
    // Use defaults if not configured yet
  }
}

async function saveAISettings(): Promise<void> {
  aiSaving.value = true;
  aiMessage.value = null;
  try {
    const { api_key_configured, ...payload } = aiSettings.value;
    await axios.put("/api/settings/ai", payload);
    aiMessage.value = "AI settings saved successfully.";
    setTimeout(() => { aiMessage.value = null; }, 3000);
    await loadAISettings();
  } catch {
    aiMessage.value = "Failed to save AI settings.";
  } finally {
    aiSaving.value = false;
  }
}

async function saveThreatIntelSettings(): Promise<void> {
  threatIntelSaving.value = true;
  threatIntelMessage.value = null;
  try {
    const payload = {
      abuseipdb_enabled: threatIntel.value.abuseipdb_enabled,
      abuseipdb_max_age: threatIntel.value.abuseipdb_max_age,
    };
    await axios.put("/api/settings/threat-intel", payload);
    threatIntelMessage.value = "Threat intelligence settings saved successfully.";
    setTimeout(() => { threatIntelMessage.value = null; }, 3000);
    await loadThreatIntelSettings();
  } catch {
    threatIntelMessage.value = "Failed to save threat intelligence settings.";
  } finally {
    threatIntelSaving.value = false;
  }
}

async function loadThreatIntelSettings(): Promise<void> {
  try {
    const { data } = await axios.get("/api/settings/threat-intel");
    threatIntel.value = {
      abuseipdb_enabled: data.abuseipdb_enabled ?? false,
      abuseipdb_api_key_configured: data.abuseipdb_api_key_configured ?? false,
      abuseipdb_max_age: data.abuseipdb_max_age ?? 90,
    };
  } catch {
    // Non-fatal, use defaults
  }
}

async function loadScanSchedule(): Promise<void> {
  try {
    const [scheduleRes, optionsRes] = await Promise.all([
      axios.get("/api/settings/scan-schedule"),
      axios.get("/api/settings/scan-schedule/options"),
    ]);
    scanSchedule.value = scheduleRes.data;
    frequencyOptions.value = optionsRes.data.frequencies ?? [];
    scanTypeOptions.value = optionsRes.data.scan_types ?? [];
  } catch {
    // Use defaults
  }
}

async function saveScanSchedule(): Promise<void> {
  scanScheduleSaving.value = true;
  scanScheduleMessage.value = null;
  try {
    await axios.put("/api/settings/scan-schedule", scanSchedule.value);
    scanScheduleMessage.value = "Scan schedule saved successfully.";
    setTimeout(() => { scanScheduleMessage.value = null; }, 3000);
  } catch {
    scanScheduleMessage.value = "Failed to save scan schedule.";
  } finally {
    scanScheduleSaving.value = false;
  }
}

onMounted(() => {
  loadNetworkSegments();
  loadNotificationSettings();
  loadAISettings();
  loadThreatIntelSettings();
  loadScanSchedule();
  loadBackups();
});

const isNightshade = computed(() => props.theme === 'nightshade');

interface BackupFile {
  filename: string;
  size: number;
  created_at: string;
}

interface RestoreResult {
  status: string;
  tables: Record<string, number>;
}

const backups = ref<BackupFile[]>([]);
const backupsLoading = ref(false);
const backupExporting = ref(false);
const backupMessage = ref<string | null>(null);
const backupRestoreFile = ref<File | null>(null);
const backupRestoring = ref(false);
const restoreResult = ref<RestoreResult | null>(null);

function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

async function loadBackups(): Promise<void> {
  backupsLoading.value = true;
  try {
    const { data } = await axios.get<BackupFile[]>("/api/backup/list");
    backups.value = data;
  } catch {
    backups.value = [];
  } finally {
    backupsLoading.value = false;
  }
}

async function exportBackup(): Promise<void> {
  backupExporting.value = true;
  backupMessage.value = null;
  try {
    const response = await axios.post("/api/backup/export", {}, { responseType: 'blob' });
    const contentDisposition = response.headers['content-disposition'];
    let filename = 'netpulse_backup.json';
    if (contentDisposition) {
      const match = contentDisposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
      if (match && match[1]) {
        filename = match[1].replace(/['"]/g, '');
      }
    }
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', filename);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
    backupMessage.value = "Backup exported successfully.";
    setTimeout(() => { backupMessage.value = null; }, 3000);
    await loadBackups();
  } catch {
    backupMessage.value = "Failed to export backup.";
  } finally {
    backupExporting.value = false;
  }
}

async function downloadBackup(filename: string): Promise<void> {
  try {
    const response = await axios.get(`/api/backup/${filename}`, { responseType: 'blob' });
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', filename);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  } catch {
    backupMessage.value = "Failed to download backup.";
  }
}

async function deleteBackup(filename: string): Promise<void> {
  try {
    await axios.delete(`/api/backup/${filename}`);
    backupMessage.value = "Backup deleted.";
    setTimeout(() => { backupMessage.value = null; }, 3000);
    await loadBackups();
  } catch {
    backupMessage.value = "Failed to delete backup.";
  }
}

function onBackupFileChange(event: Event): void {
  const target = event.target as HTMLInputElement;
  if (target.files && target.files.length > 0) {
    backupRestoreFile.value = target.files[0];
  }
}

async function restoreBackup(): Promise<void> {
  if (!backupRestoreFile.value) return;
  backupRestoring.value = true;
  backupMessage.value = null;
  restoreResult.value = null;
  try {
    const formData = new FormData();
    formData.append('file', backupRestoreFile.value);
    const { data } = await axios.post<RestoreResult>("/api/backup/restore", formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    restoreResult.value = data;
    backupMessage.value = "Restore completed successfully.";
    backupRestoreFile.value = null;
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    if (fileInput) fileInput.value = '';
    setTimeout(() => { backupMessage.value = null; }, 5000);
  } catch {
    backupMessage.value = "Failed to restore backup.";
  } finally {
    backupRestoring.value = false;
  }
}

type SettingsTab = "general" | "ai" | "notifications" | "network" | "schedule" | "threat" | "backup";
const activeSettingsTab = ref<SettingsTab>("general");

const settingsTabs: { key: SettingsTab; label: string; icon: string }[] = [
  { key: "general", label: "General", icon: "M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z M15 12a3 3 0 11-6 0 3 3 0 016 0z" },
  { key: "ai", label: "AI Assistant", icon: "M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" },
  { key: "notifications", label: "Alerts", icon: "M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" },
  { key: "network", label: "Network", icon: "M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9" },
  { key: "schedule", label: "Scheduler", icon: "M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" },
  { key: "threat", label: "Threat Intel", icon: "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" },
  { key: "backup", label: "Backup", icon: "M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" },
];
</script>

<template>
  <div class="space-y-4 np-fade-in">
    <div class="flex gap-1 flex-wrap border-b pb-0" style="border-color: var(--np-border)">
      <button
        v-for="tab in settingsTabs"
        :key="tab.key"
        type="button"
        @click="activeSettingsTab = tab.key"
        class="flex items-center gap-1.5 px-3 py-2.5 text-xs font-medium transition-all duration-300 border-b-2 -mb-px"
        :class="[
          activeSettingsTab === tab.key
            ? 'border-[var(--np-accent-primary)] text-[var(--np-accent-primary)]'
            : 'border-transparent text-[var(--np-muted-text)] hover:text-[var(--np-text)]'
        ]"
      >
        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" :d="tab.icon" />
        </svg>
        {{ tab.label }}
      </button>
    </div>

    <div v-if="activeSettingsTab === 'general'" class="np-fade-in">
      <section class="np-panel p-4 space-y-4">
        <header class="np-panel-header -mx-4 -mt-4 mb-2 px-4">
          <div class="flex flex-col">
            <span class="np-panel-title">Console Settings</span>
            <span class="text-[0.7rem] text-[var(--np-muted-text)]">
              Tune how dense the dashboard feels.
            </span>
          </div>
        </header>

        <div class="np-settings-section">
          <p class="np-settings-section-title">View Density</p>
          <p class="text-[0.75rem] mb-3" :class="isNightshade ? 'text-teal-100/80' : 'text-slate-300'">
            Choose between a detailed operator console and a quick-look mode.
          </p>
          <div class="flex flex-wrap gap-2">
            <button
              type="button"
              @click="setInfoMode('full')"
              class="rounded border px-4 py-2 text-[0.75rem] font-medium transition-all"
              :class="[
                localInfoMode === 'full'
                  ? isNightshade
                    ? 'border-emerald-400/80 bg-emerald-500/25 text-emerald-300 ring-1 ring-emerald-400/50'
                    : 'border-amber-500 bg-amber-500/20 text-amber-300 ring-1 ring-amber-500/50'
                  : isNightshade
                    ? 'border-teal-400/40 text-teal-200 hover:bg-teal-500/10'
                    : 'border-amber-600/40 text-amber-200/80 hover:bg-amber-600/10'
              ]"
            >
              Full Detail
            </button>
            <button
              type="button"
              @click="setInfoMode('compact')"
              class="rounded border px-4 py-2 text-[0.75rem] font-medium transition-all"
              :class="[
                localInfoMode === 'compact'
                  ? isNightshade
                    ? 'border-emerald-400/80 bg-emerald-500/25 text-emerald-300 ring-1 ring-emerald-400/50'
                    : 'border-amber-500 bg-amber-500/20 text-amber-300 ring-1 ring-amber-500/50'
                  : isNightshade
                    ? 'border-teal-400/40 text-teal-200 hover:bg-teal-500/10'
                    : 'border-amber-600/40 text-amber-200/80 hover:bg-amber-600/10'
              ]"
            >
              Quick View
            </button>
          </div>
          <p class="mt-3 text-[0.7rem]" :class="isNightshade ? 'text-teal-100/60' : 'text-slate-400'">
            The Pulse chart and dashboard widgets adapt to this setting.
          </p>
        </div>

        <div class="np-settings-section">
          <p class="np-settings-section-title">Current Theme</p>
          <p class="text-[0.75rem]" :class="isNightshade ? 'text-teal-100/80' : 'text-slate-300'">
            <span class="font-semibold" :class="isNightshade ? 'text-teal-300' : 'text-amber-300'">
              {{ theme === "nightshade" ? "Nightshade" : "SysAdmin" }}
            </span>
            &mdash; Use the toggle in the header to switch.
          </p>
        </div>
      </section>
    </div>

    <div v-else-if="activeSettingsTab === 'ai'" class="np-fade-in">
      <section class="np-panel p-4 space-y-4">
        <header class="np-panel-header -mx-4 -mt-4 mb-2 px-4">
          <div class="flex flex-col">
            <span class="np-panel-title">AI Assistant</span>
            <span class="text-[0.7rem] text-[var(--np-muted-text)]">
              Configure the AI chatbot for network guidance.
            </span>
          </div>
        </header>

        <div class="space-y-4 text-xs">
          <div class="np-settings-section">
            <div class="flex items-center justify-between mb-3">
              <p class="np-settings-section-title mb-0">AI Chatbot</p>
              <ToggleSwitch v-model="aiSettings.enabled" :theme="theme" />
            </div>
            
            <div v-if="aiSettings.enabled" class="space-y-3">
              <label class="flex flex-col gap-1">
                <span :class="isNightshade ? 'text-teal-200' : 'text-slate-300'">Provider</span>
                <select
                  v-model="aiSettings.provider"
                  class="np-neon-input rounded px-3 py-2 text-[0.8rem]"
                >
                  <option value="openai">OpenAI</option>
                  <option value="anthropic">Anthropic (Claude)</option>
                  <option value="google">Google (Gemini)</option>
                  <option value="groq">Groq</option>
                  <option value="together">Together AI</option>
                  <option value="ollama">Ollama (Local)</option>
                  <option value="custom">Custom / Other</option>
                </select>
              </label>

              <template v-if="aiSettings.provider === 'custom'">
                <label class="flex flex-col gap-1">
                  <span :class="isNightshade ? 'text-teal-200' : 'text-slate-300'">Base URL</span>
                  <input
                    v-model="aiSettings.custom_base_url"
                    type="text"
                    placeholder="https://api.example.com/v1"
                    class="np-neon-input rounded px-3 py-2 text-[0.8rem] font-mono"
                  />
                  <span class="text-[0.65rem] mt-1" :class="isNightshade ? 'text-teal-100/50' : 'text-slate-500'">
                    OpenAI-compatible endpoint URL
                  </span>
                </label>
                <label class="flex flex-col gap-1">
                  <span :class="isNightshade ? 'text-teal-200' : 'text-slate-300'">Model Name</span>
                  <input
                    v-model="aiSettings.custom_model"
                    type="text"
                    placeholder="llama-3.1-70b"
                    class="np-neon-input rounded px-3 py-2 text-[0.8rem] font-mono"
                  />
                </label>
              </template>

              <label v-else class="flex flex-col gap-1">
                <span :class="isNightshade ? 'text-teal-200' : 'text-slate-300'">Model</span>
                <select
                  v-model="aiSettings.model"
                  class="np-neon-input rounded px-3 py-2 text-[0.8rem]"
                >
                  <template v-if="aiSettings.provider === 'openai'">
                    <option value="gpt-4o">GPT-4o</option>
                    <option value="gpt-4o-mini">GPT-4o Mini</option>
                    <option value="gpt-4-turbo">GPT-4 Turbo</option>
                  </template>
                  <template v-else-if="aiSettings.provider === 'anthropic'">
                    <option value="claude-3-5-sonnet-20241022">Claude 3.5 Sonnet</option>
                    <option value="claude-3-opus-20240229">Claude 3 Opus</option>
                    <option value="claude-3-haiku-20240307">Claude 3 Haiku</option>
                  </template>
                  <template v-else-if="aiSettings.provider === 'google'">
                    <option value="gemini-1.5-pro">Gemini 1.5 Pro</option>
                    <option value="gemini-1.5-flash">Gemini 1.5 Flash</option>
                  </template>
                  <template v-else-if="aiSettings.provider === 'groq'">
                    <option value="llama-3.1-70b-versatile">Llama 3.1 70B</option>
                    <option value="llama-3.1-8b-instant">Llama 3.1 8B</option>
                    <option value="mixtral-8x7b-32768">Mixtral 8x7B</option>
                  </template>
                  <template v-else-if="aiSettings.provider === 'together'">
                    <option value="meta-llama/Llama-3-70b-chat-hf">Llama 3 70B</option>
                    <option value="mistralai/Mixtral-8x7B-Instruct-v0.1">Mixtral 8x7B</option>
                  </template>
                  <template v-else-if="aiSettings.provider === 'ollama'">
                    <option value="llama3.1">Llama 3.1</option>
                    <option value="mistral">Mistral</option>
                    <option value="codellama">Code Llama</option>
                  </template>
                </select>
              </label>

              <div class="flex items-center justify-between py-2">
                <span :class="isNightshade ? 'text-teal-200' : 'text-slate-300'">API Key</span>
                <span v-if="aiSettings.api_key_configured" class="flex items-center gap-1.5" :class="isNightshade ? 'text-emerald-400' : 'text-green-500'">
                  <svg class="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" /></svg>
                  Configured via environment
                </span>
                <span v-else class="flex items-center gap-1.5 text-amber-400">
                  <svg class="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" /></svg>
                  Not configured — set via .env file
                </span>
              </div>
            </div>
          </div>

          <div class="flex items-center justify-between pt-2">
            <p v-if="aiMessage" class="text-[0.7rem]" :class="aiMessage.includes('Failed') ? 'text-rose-400' : (isNightshade ? 'text-emerald-400' : 'text-green-500')">
              {{ aiMessage }}
            </p>
            <div class="ml-auto">
              <button
                type="button"
                @click="saveAISettings"
                :disabled="aiSaving"
                class="np-cyber-btn rounded px-4 py-2 text-[0.75rem]"
              >
                {{ aiSaving ? "Saving..." : "Save AI Settings" }}
              </button>
            </div>
          </div>
        </div>
      </section>
    </div>

    <div v-else-if="activeSettingsTab === 'notifications'" class="np-fade-in">
      <section class="np-panel p-4 space-y-4">
        <header class="np-panel-header -mx-4 -mt-4 mb-2 px-4">
          <div class="flex flex-col">
            <span class="np-panel-title">Notifications</span>
            <span class="text-[0.7rem] text-[var(--np-muted-text)]">
              Configure email and WhatsApp alerts for network events.
            </span>
          </div>
        </header>

        <div class="space-y-4 text-xs">
          <!-- Email Settings -->
          <div class="np-settings-section">
            <div class="flex items-center justify-between mb-3">
              <p class="np-settings-section-title mb-0">Email Alerts</p>
              <ToggleSwitch v-model="notifications.email_enabled" :theme="theme" />
            </div>
            <div v-if="notifications.email_enabled" class="space-y-3">
              <label class="flex flex-col gap-1">
                <span :class="isNightshade ? 'text-teal-200' : 'text-slate-300'">Email Address</span>
                <input
                  v-model="notifications.email_address"
                  type="email"
                  placeholder="admin@example.com"
                  class="np-neon-input rounded px-3 py-2 text-[0.8rem]"
                />
              </label>
            </div>
          </div>

          <!-- WhatsApp Settings -->
          <div class="np-settings-section">
            <div class="flex items-center justify-between mb-3">
              <p class="np-settings-section-title mb-0">WhatsApp Alerts</p>
              <ToggleSwitch v-model="notifications.whatsapp_enabled" :theme="theme" />
            </div>
            <div v-if="notifications.whatsapp_enabled" class="space-y-3">
              <label class="flex flex-col gap-1">
                <span :class="isNightshade ? 'text-teal-200' : 'text-slate-300'">WhatsApp Number</span>
                <input
                  v-model="notifications.whatsapp_number"
                  type="tel"
                  placeholder="+1 555 123 4567"
                  class="np-neon-input rounded px-3 py-2 text-[0.8rem]"
                />
              </label>
            </div>
          </div>

          <!-- Alert Types -->
          <div class="np-settings-section">
            <p class="np-settings-section-title">Alert Types</p>
            <div class="space-y-3">
              <div class="flex items-center justify-between">
                <span :class="isNightshade ? 'text-teal-100' : 'text-slate-300'">Critical Alerts</span>
                <ToggleSwitch v-model="notifications.alert_on_critical" :theme="theme" />
              </div>
              <div class="flex items-center justify-between">
                <span :class="isNightshade ? 'text-teal-100' : 'text-slate-300'">Warning Alerts</span>
                <ToggleSwitch v-model="notifications.alert_on_warning" :theme="theme" />
              </div>
              <div class="flex items-center justify-between">
                <span :class="isNightshade ? 'text-teal-100' : 'text-slate-300'">Device Down</span>
                <ToggleSwitch v-model="notifications.alert_on_device_down" :theme="theme" />
              </div>
              <div class="flex items-center justify-between">
                <span :class="isNightshade ? 'text-teal-100' : 'text-slate-300'">Daily Digest</span>
                <ToggleSwitch v-model="notifications.daily_digest" :theme="theme" />
              </div>
            </div>
          </div>

          <div class="flex items-center justify-between pt-2">
            <p v-if="notificationsMessage" class="text-[0.7rem]" :class="notificationsMessage.includes('Failed') ? 'text-rose-400' : (isNightshade ? 'text-emerald-400' : 'text-green-500')">
              {{ notificationsMessage }}
            </p>
            <div class="ml-auto">
              <button
                type="button"
                @click="saveNotificationSettings"
                :disabled="notificationsSaving"
                class="np-cyber-btn rounded px-4 py-2 text-[0.75rem]"
              >
                {{ notificationsSaving ? "Saving..." : "Save Notifications" }}
              </button>
            </div>
          </div>
        </div>
      </section>
    </div>

    <div v-else-if="activeSettingsTab === 'threat'" class="np-fade-in">
      <section class="np-panel p-4 space-y-4">
        <header class="np-panel-header -mx-4 -mt-4 mb-2 px-4">
          <div class="flex flex-col">
            <span class="np-panel-title">Threat Intelligence</span>
            <span class="text-[0.7rem] text-[var(--np-muted-text)]">
              Configure external APIs for IP reputation checking.
            </span>
          </div>
        </header>

        <div class="space-y-4 text-xs">
          <!-- AbuseIPDB Settings -->
          <div class="np-settings-section">
            <div class="flex items-center justify-between mb-3">
              <p class="np-settings-section-title mb-0">AbuseIPDB</p>
              <ToggleSwitch v-model="threatIntel.abuseipdb_enabled" :theme="theme" />
            </div>
            <div v-if="threatIntel.abuseipdb_enabled" class="space-y-3">
              <div class="flex items-center justify-between py-2">
                <span :class="isNightshade ? 'text-teal-200' : 'text-slate-300'">API Key</span>
                <span v-if="threatIntel.abuseipdb_api_key_configured" class="flex items-center gap-1.5" :class="isNightshade ? 'text-emerald-400' : 'text-green-500'">
                  <svg class="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" /></svg>
                  Configured via environment
                </span>
                <span v-else class="flex items-center gap-1.5 text-amber-400">
                  <svg class="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" /></svg>
                  Not configured — set via .env file
                </span>
              </div>
              <label class="flex flex-col gap-1">
                <span :class="isNightshade ? 'text-teal-200' : 'text-slate-300'">Max Report Age (days)</span>
                <input
                  v-model.number="threatIntel.abuseipdb_max_age"
                  type="number"
                  min="1"
                  max="365"
                  placeholder="90"
                  class="np-neon-input rounded px-3 py-2 text-[0.8rem] w-24"
                />
                <span class="text-[0.65rem] mt-1" :class="isNightshade ? 'text-teal-100/50' : 'text-slate-500'">
                  Only consider reports from the last N days (1-365)
                </span>
              </label>
            </div>
          </div>

          <div class="flex items-center justify-between pt-2">
            <p v-if="threatIntelMessage" class="text-[0.7rem]" :class="threatIntelMessage.includes('Failed') ? 'text-rose-400' : (isNightshade ? 'text-emerald-400' : 'text-green-500')">
              {{ threatIntelMessage }}
            </p>
            <div class="ml-auto">
              <button
                type="button"
                @click="saveThreatIntelSettings"
                :disabled="threatIntelSaving"
                class="np-cyber-btn rounded px-4 py-2 text-[0.75rem]"
              >
                {{ threatIntelSaving ? "Saving..." : "Save Threat Intel" }}
              </button>
            </div>
          </div>
        </div>
      </section>
    </div>

    <div v-else-if="activeSettingsTab === 'schedule'" class="np-fade-in">
      <section class="np-panel p-4 space-y-4">
      <header class="np-panel-header -mx-4 -mt-4 mb-2 px-4">
        <div class="flex flex-col">
          <span class="np-panel-title">Scan Scheduler</span>
          <span class="text-[0.7rem] text-[var(--np-muted-text)]">
            Schedule automated network scans.
          </span>
        </div>
      </header>

      <div class="np-settings-section">
        <div class="flex items-center justify-between mb-4">
          <div>
            <p class="np-settings-section-title">Enable Scheduled Scans</p>
            <p class="text-[0.7rem]" :class="isNightshade ? 'text-teal-100/60' : 'text-slate-400'">
              Automatically run scans on a recurring schedule.
            </p>
          </div>
          <ToggleSwitch v-model="scanSchedule.enabled" :theme="theme" />
        </div>

        <div v-if="scanSchedule.enabled" class="space-y-4 mt-4 pt-4 border-t" :class="isNightshade ? 'border-teal-400/20' : 'border-slate-600/30'">
          <div class="grid grid-cols-2 gap-4">
            <label class="flex flex-col gap-1">
              <span class="text-[0.75rem]" :class="isNightshade ? 'text-teal-200' : 'text-slate-300'">Frequency</span>
              <select
                v-model="scanSchedule.frequency"
                class="np-neon-input rounded px-3 py-2 text-[0.8rem]"
              >
                <option v-for="opt in frequencyOptions" :key="opt.value" :value="opt.value">
                  {{ opt.label }}
                </option>
              </select>
            </label>
            <label class="flex flex-col gap-1">
              <span class="text-[0.75rem]" :class="isNightshade ? 'text-teal-200' : 'text-slate-300'">Time (24h format)</span>
              <input
                v-model="scanSchedule.time"
                type="time"
                class="np-neon-input rounded px-3 py-2 text-[0.8rem]"
              />
            </label>
          </div>

          <label class="flex flex-col gap-1">
            <span class="text-[0.75rem]" :class="isNightshade ? 'text-teal-200' : 'text-slate-300'">Scan Type</span>
            <select
              v-model="scanSchedule.scan_type"
              class="np-neon-input rounded px-3 py-2 text-[0.8rem]"
            >
              <option v-for="opt in scanTypeOptions" :key="opt.value" :value="opt.value">
                {{ opt.label }} - {{ opt.description }}
              </option>
            </select>
          </label>

          <div class="flex items-center justify-between">
            <div>
              <p class="text-[0.75rem]" :class="isNightshade ? 'text-teal-200' : 'text-slate-300'">Notify on Complete</p>
              <p class="text-[0.65rem]" :class="isNightshade ? 'text-teal-100/60' : 'text-slate-400'">
                Send notification when scheduled scan finishes.
              </p>
            </div>
            <ToggleSwitch v-model="scanSchedule.notify_on_complete" :theme="theme" />
          </div>
        </div>
      </div>

      <div class="flex items-center justify-end gap-4 mt-4">
        <p v-if="scanScheduleMessage" class="text-[0.75rem]" :class="scanScheduleMessage.includes('success') ? (isNightshade ? 'text-emerald-400' : 'text-green-500') : 'text-rose-400'">
          {{ scanScheduleMessage }}
        </p>
        <button
          type="button"
          @click="saveScanSchedule"
          :disabled="scanScheduleSaving"
          class="np-cyber-btn rounded px-4 py-2 text-[0.75rem]"
        >
          {{ scanScheduleSaving ? "Saving..." : "Save Schedule" }}
        </button>
      </div>
    </section>
    </div>

    <div v-else-if="activeSettingsTab === 'backup'" class="np-fade-in">
      <section class="np-panel p-4 space-y-4">
        <header class="np-panel-header -mx-4 -mt-4 mb-2 px-4">
          <div class="flex flex-col">
            <span class="np-panel-title">Backup &amp; Restore</span>
            <span class="text-[0.7rem] text-[var(--np-muted-text)]">
              Export, download, and restore database backups.
            </span>
          </div>
        </header>

        <div class="space-y-4 text-xs">
          <div class="np-settings-section">
            <p class="np-settings-section-title">Export Database</p>
            <p class="text-[0.75rem] mb-3" :class="isNightshade ? 'text-teal-100/80' : 'text-slate-300'">
              Export all devices, uptime targets, and network segments to a JSON file.
            </p>
            <button
              type="button"
              @click="exportBackup"
              :disabled="backupExporting"
              class="np-cyber-btn rounded px-4 py-2 text-[0.75rem]"
            >
              {{ backupExporting ? "Exporting..." : "Export Database" }}
            </button>
          </div>

          <div class="np-settings-section">
            <p class="np-settings-section-title">Available Backups</p>
            <p v-if="backupsLoading" :class="isNightshade ? 'text-teal-100/80' : 'text-slate-300'">
              Loading backups...
            </p>
            <div v-else-if="backups.length === 0" class="text-center py-4">
              <p :class="isNightshade ? 'text-teal-100/60' : 'text-slate-500'">
                No backups found. Export a backup to get started.
              </p>
            </div>
            <div v-else class="space-y-2">
              <div
                v-for="backup in backups"
                :key="backup.filename"
                class="flex items-center justify-between rounded-lg border p-3 transition-all"
                :class="isNightshade ? 'border-teal-400/30 bg-black/30' : 'border-amber-600/20 bg-slate-800/30'"
              >
                <div class="flex-1 min-w-0">
                  <p class="font-mono text-[0.75rem] truncate" :class="isNightshade ? 'text-teal-200' : 'text-amber-200'">
                    {{ backup.filename }}
                  </p>
                  <p class="text-[0.65rem] mt-0.5" :class="isNightshade ? 'text-teal-100/60' : 'text-slate-400'">
                    {{ formatFileSize(backup.size) }} &middot; {{ new Date(backup.created_at).toLocaleString() }}
                  </p>
                </div>
                <div class="flex gap-2 ml-3 shrink-0">
                  <button
                    type="button"
                    @click="downloadBackup(backup.filename)"
                    class="rounded px-2.5 py-1 text-[0.65rem] font-medium border transition-all"
                    :class="isNightshade ? 'border-teal-400/40 text-teal-300 hover:bg-teal-500/15' : 'border-amber-600/40 text-amber-300 hover:bg-amber-600/15'"
                  >
                    Download
                  </button>
                  <button
                    type="button"
                    @click="deleteBackup(backup.filename)"
                    class="rounded px-2.5 py-1 text-[0.65rem] font-medium border transition-all"
                    :class="isNightshade ? 'border-rose-400/40 text-rose-300 hover:bg-rose-500/20' : 'border-red-500/40 text-red-400 hover:bg-red-600/20'"
                  >
                    Delete
                  </button>
                </div>
              </div>
            </div>
          </div>

          <div class="np-settings-section">
            <p class="np-settings-section-title">Restore from Backup</p>
            <p class="text-[0.75rem] mb-1" :class="isNightshade ? 'text-teal-100/80' : 'text-slate-300'">
              Upload a JSON backup file to restore data.
            </p>
            <p class="text-[0.7rem] mb-3 font-medium" :class="isNightshade ? 'text-rose-300/80' : 'text-red-400/80'">
              ⚠ This will replace existing data in the restored tables.
            </p>
            <div class="flex items-center gap-3 flex-wrap">
              <input
                type="file"
                accept=".json"
                @change="onBackupFileChange"
                class="np-neon-input rounded px-3 py-2 text-[0.8rem] file:mr-3 file:rounded file:border-0 file:px-3 file:py-1 file:text-[0.7rem] file:font-medium"
                :class="isNightshade ? 'file:bg-teal-500/20 file:text-teal-300' : 'file:bg-amber-500/20 file:text-amber-300'"
              />
              <button
                type="button"
                @click="restoreBackup"
                :disabled="backupRestoring || !backupRestoreFile"
                class="np-cyber-btn rounded px-4 py-2 text-[0.75rem]"
                :class="{ 'opacity-50 cursor-not-allowed': !backupRestoreFile }"
              >
                {{ backupRestoring ? "Restoring..." : "Restore from Backup" }}
              </button>
            </div>

            <div v-if="restoreResult" class="mt-3 rounded-lg border p-3" :class="isNightshade ? 'border-emerald-400/30 bg-emerald-500/10' : 'border-green-500/30 bg-green-600/10'">
              <p class="text-[0.75rem] font-medium mb-2" :class="isNightshade ? 'text-emerald-300' : 'text-green-400'">
                Restore Complete
              </p>
              <div class="space-y-1">
                <div
                  v-for="(count, table) in restoreResult.tables"
                  :key="table"
                  class="flex items-center justify-between text-[0.7rem]"
                >
                  <span :class="isNightshade ? 'text-teal-100/80' : 'text-slate-300'">{{ table }}</span>
                  <span class="font-mono" :class="isNightshade ? 'text-teal-300' : 'text-amber-300'">{{ count }} records</span>
                </div>
              </div>
            </div>
          </div>

          <div v-if="backupMessage" class="pt-1">
            <p class="text-[0.7rem]" :class="backupMessage.includes('Failed') ? 'text-rose-400' : (isNightshade ? 'text-emerald-400' : 'text-green-500')">
              {{ backupMessage }}
            </p>
          </div>
        </div>
      </section>
    </div>

    <div v-else-if="activeSettingsTab === 'network'" class="np-fade-in">
      <section class="np-panel p-4 space-y-4">
      <header class="np-panel-header -mx-4 -mt-4 mb-2 px-4">
        <div class="flex flex-col">
          <span class="np-panel-title">Network Segments</span>
          <span class="text-[0.7rem] text-[var(--np-muted-text)]">
            Configure subnets for segmented network scanning.
          </span>
        </div>
        <button
          type="button"
          @click="showAddSegment = !showAddSegment"
          class="np-cyber-btn rounded px-3 py-1.5 text-[0.75rem]"
        >
          {{ showAddSegment ? 'Cancel' : '+ Add Segment' }}
        </button>
      </header>

      <div v-if="showAddSegment" class="np-settings-section">
        <p class="np-settings-section-title">New Network Segment</p>
        <div class="grid grid-cols-2 gap-3 mb-3">
          <label class="flex flex-col gap-1">
            <span class="text-[0.75rem]" :class="isNightshade ? 'text-teal-200' : 'text-slate-300'">Segment Name</span>
            <input
              v-model="newSegment.name"
              type="text"
              placeholder="e.g. Production LAN"
              class="np-neon-input rounded px-3 py-2 text-[0.8rem]"
            />
          </label>
          <label class="flex flex-col gap-1">
            <span class="text-[0.75rem]" :class="isNightshade ? 'text-teal-200' : 'text-slate-300'">CIDR Range</span>
            <input
              v-model="newSegment.cidr"
              type="text"
              placeholder="e.g. 192.168.1.0/24"
              class="np-neon-input rounded px-3 py-2 text-[0.8rem] font-mono"
            />
          </label>
          <label class="flex flex-col gap-1">
            <span class="text-[0.75rem]" :class="isNightshade ? 'text-teal-200' : 'text-slate-300'">VLAN ID (optional)</span>
            <input
              v-model.number="newSegment.vlan_id"
              type="number"
              placeholder="e.g. 100"
              class="np-neon-input rounded px-3 py-2 text-[0.8rem]"
            />
          </label>
          <label class="flex flex-col gap-1">
            <span class="text-[0.75rem]" :class="isNightshade ? 'text-teal-200' : 'text-slate-300'">Description</span>
            <input
              v-model="newSegment.description"
              type="text"
              placeholder="e.g. Main office network"
              class="np-neon-input rounded px-3 py-2 text-[0.8rem]"
            />
          </label>
        </div>
        <div class="flex justify-end">
          <button
            type="button"
            @click="addNetworkSegment"
            class="np-cyber-btn rounded px-4 py-2 text-[0.75rem]"
          >
            Add Segment
          </button>
        </div>
      </div>

      <div class="text-xs">
        <p v-if="segmentsLoading" :class="isNightshade ? 'text-teal-100/80' : 'text-slate-300'">
          Loading network segments...
        </p>
        <p v-else-if="segmentsError" class="text-rose-400">
          {{ segmentsError }}
        </p>
        <div v-else-if="segments.length === 0" class="np-settings-section text-center py-8">
          <p :class="isNightshade ? 'text-teal-100/60' : 'text-slate-500'">
            No network segments configured. Add a segment to enable multi-subnet scanning.
          </p>
        </div>
        <div v-else class="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          <div
            v-for="seg in segments"
            :key="seg.id"
            class="rounded-lg border p-4 transition-all"
            :class="[
              seg.scan_enabled
                ? isNightshade
                  ? 'border-teal-400/40 bg-black/40'
                  : 'border-amber-600/30 bg-slate-800/40'
                : isNightshade
                  ? 'border-teal-400/20 bg-black/20 opacity-60'
                  : 'border-amber-600/15 bg-slate-800/20 opacity-60'
            ]"
          >
            <div class="flex items-start justify-between gap-2">
              <div>
                <h4 class="font-semibold text-[0.85rem]" :class="isNightshade ? 'text-teal-200' : 'text-amber-200'">
                  {{ seg.name }}
                </h4>
                <p class="font-mono text-[0.75rem] mt-1" :class="isNightshade ? 'text-teal-400' : 'text-amber-400'">
                  {{ seg.cidr }}
                </p>
                <p v-if="seg.vlan_id" class="text-[0.7rem] mt-1" :class="isNightshade ? 'text-teal-100/60' : 'text-slate-400'">
                  VLAN {{ seg.vlan_id }}
                </p>
                <p v-if="seg.description" class="text-[0.7rem] mt-1" :class="isNightshade ? 'text-teal-100/50' : 'text-slate-500'">
                  {{ seg.description }}
                </p>
              </div>
              <div class="flex flex-col gap-1">
                <button
                  type="button"
                  @click="toggleSegmentScan(seg)"
                  class="rounded px-2 py-1 text-[0.65rem] uppercase tracking-wide font-medium transition-all"
                  :class="[
                    seg.scan_enabled
                      ? isNightshade
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-400/40'
                        : 'bg-green-600/20 text-green-400 border border-green-500/40'
                      : isNightshade
                        ? 'bg-gray-500/20 text-gray-400 border border-gray-500/40'
                        : 'bg-slate-600/20 text-slate-400 border border-slate-500/40'
                  ]"
                >
                  {{ seg.scan_enabled ? 'Active' : 'Paused' }}
                </button>
                <button
                  type="button"
                  @click="deleteSegment(seg)"
                  class="rounded px-2 py-1 text-[0.65rem] uppercase tracking-wide font-medium transition-all border"
                  :class="isNightshade ? 'border-rose-400/40 text-rose-300 hover:bg-rose-500/20' : 'border-red-500/40 text-red-400 hover:bg-red-600/20'"
                >
                  Delete
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
    </div>
  </div>
</template>
