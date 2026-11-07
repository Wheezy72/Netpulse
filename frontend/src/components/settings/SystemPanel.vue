<script setup lang="ts">
/**
 * Instance health, for Settings.
 *
 * The three things this install needs are the API itself, nmap and Redis.
 * Redis is a cache: losing it never breaks a sign-in, it only costs the
 * shared throttle window and the token revocation list, so a row here has to
 * say both what is wrong and what still works. Before this panel the only
 * sign that Redis had stopped was a warning in the log.
 */
import axios from "axios";
import { computed, onMounted, ref } from "vue";

interface RedisReport {
  reachable: boolean;
  error: string | null;
  retry_in_seconds: number;
}

interface ReadyReport {
  status: string;
  nmap: { available: boolean; version: string | null };
  redis: RedisReport;
}

type Tone = "ok" | "warn" | "down";

interface Row {
  key: string;
  label: string;
  tone: Tone;
  value: string;
  detail: string;
}

const report = ref<ReadyReport | null>(null);
const unreachable = ref(false);
const checking = ref(false);
const checkedAt = ref<Date | null>(null);

const TONE_TEXT: Record<Tone, string> = {
  ok: "text-[var(--np-accent)]",
  warn: "text-amber-400",
  down: "text-[var(--np-danger)]",
};

const TONE_DOT: Record<Tone, string> = {
  ok: "bg-emerald-400",
  warn: "bg-amber-400",
  down: "bg-rose-400",
};

// The API reports an exception class, which tells an operator nothing on its
// own. These are the shapes a stopped cache actually takes.
const ERROR_HINTS: Record<string, string> = {
  ConnectionError: "connection refused",
  TimeoutError: "timed out",
  OSError: "host unreachable",
  RuntimeError: "connection pool never started",
};

const rows = computed<Row[]>(() => {
  const data = report.value;
  if (!data) {
    return [
      {
        key: "api",
        label: "API",
        tone: unreachable.value ? "down" : "warn",
        value: unreachable.value ? "Not answering" : "Checking…",
        detail: unreachable.value
          ? "This page cannot reach its own API. Check that the backend container is running."
          : "",
      },
    ];
  }

  const redis = data.redis;
  const retry = Math.ceil(redis.retry_in_seconds);

  return [
    {
      key: "api",
      label: "API",
      tone: "ok" as Tone,
      value: "Answering",
      detail: "The console and the API are the same process, so this page loading means it is up.",
    },
    {
      key: "nmap",
      label: "nmap",
      tone: data.nmap.available ? ("ok" as Tone) : ("down" as Tone),
      value: data.nmap.available ? `${data.nmap.version ?? "installed"}` : "Missing",
      detail: data.nmap.available
        ? "Deep scans and OS detection run through it."
        : "Deep scans will fail until nmap is installed in the container.",
    },
    {
      key: "redis",
      label: "Redis",
      tone: redis.reachable ? ("ok" as Tone) : ("warn" as Tone),
      value: redis.reachable ? "Connected" : "Not reachable",
      detail: redis.reachable
        ? "Shared cache for the sign-in throttle and session revocation."
        : [
            "NetPulse is using its in-process fallback: sign-in still works, but the throttle window is per process.",
            redis.error ? `Last error: ${ERROR_HINTS[redis.error] ?? redis.error}.` : "",
            retry > 0 ? `Left alone for another ${retry}s.` : "",
          ]
            .filter(Boolean)
            .join(" "),
    },
  ];
});

const healthyCount = computed(() => rows.value.filter((row) => row.tone === "ok").length);

const summary = computed(() => {
  if (!report.value) return unreachable.value ? "The API did not answer." : "Checking the services this install needs…";
  if (healthyCount.value === rows.value.length) return "Everything this install needs is running.";
  return `${rows.value.length - healthyCount.value} of ${rows.value.length} services need attention.`;
});

async function check(): Promise<void> {
  checking.value = true;
  try {
    const { data, status } = await axios.get<ReadyReport>("/api/health/ready", {
      // 503 means nmap is missing, and the body still carries the report.
      validateStatus: () => true,
    });
    if ((status >= 200 && status < 300) || status === 503) {
      report.value = data;
      unreachable.value = false;
    } else {
      report.value = null;
      unreachable.value = true;
    }
  } catch {
    report.value = null;
    unreachable.value = true;
  } finally {
    checkedAt.value = new Date();
    checking.value = false;
  }
}

onMounted(check);
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between gap-3">
      <p class="text-[0.7rem] font-semibold text-[var(--np-text-dim)]">{{ summary }}</p>
      <button
        type="button"
        class="np-cyber-btn shrink-0 rounded px-4 py-2 text-[0.75rem]"
        :disabled="checking"
        @click="check"
      >
        {{ checking ? "Checking…" : "Check again" }}
      </button>
    </div>

    <div class="np-settings-section">
      <div
        v-for="row in rows"
        :key="row.key"
        class="flex items-start justify-between gap-4 py-3 border-b border-[var(--np-border-subtle)] last:border-b-0"
      >
        <div class="flex min-w-0 items-start gap-2.5">
          <span class="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full" :class="TONE_DOT[row.tone]" />
          <div class="min-w-0">
            <p class="text-[0.8rem] font-semibold np-info-card-value">{{ row.label }}</p>
            <p v-if="row.detail" class="mt-0.5 text-[0.7rem] leading-relaxed np-info-card-text">
              {{ row.detail }}
            </p>
          </div>
        </div>
        <span class="shrink-0 font-mono text-[0.7rem] font-bold" :class="TONE_TEXT[row.tone]">
          {{ row.value }}
        </span>
      </div>
    </div>

    <p v-if="checkedAt" class="text-[0.68rem] leading-relaxed text-[var(--np-text-dim)]">
      Checked at {{ checkedAt.toLocaleTimeString() }}. After a failed check the cache is left alone for
      twenty seconds, so this page stays fast while Redis is down.
    </p>
  </div>
</template>
