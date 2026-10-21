<script setup lang="ts">
import { useRoute, useRouter } from "vue-router";

const router = useRouter();
const route = useRoute();

const match = Array.isArray(route.params.pathMatch) ? route.params.pathMatch.join("/") : route.params.pathMatch;
const attemptedPath = route.path || (match ? `/${match}` : "/");

const quickLinks = [
  { label: "Dashboard", to: "/dashboard" },
  { label: "Topology", to: "/topology" },
  { label: "Devices", to: "/devices" },
  { label: "Toolbox", to: "/toolbox" },
];
</script>

<template>
  <div class="flex min-h-[70vh] flex-col items-center justify-center text-center">
    <p class="np-brand-text font-mono text-[0.65rem] uppercase tracking-[0.4em]">Lost packet</p>

    <h1 class="mt-3 font-mono text-6xl font-bold tracking-tight text-[var(--np-text)]">404</h1>

    <p class="mt-3 max-w-md font-mono text-xs leading-relaxed text-[var(--np-text-muted)]">
      Nothing is listening at
      <span class="np-brand-text font-bold">{{ attemptedPath }}</span>
      — no route answered, so the request was dropped.
    </p>

    <div class="mt-8 flex flex-wrap items-center justify-center gap-2">
      <button
        type="button"
        class="np-cyber-btn px-5 py-2.5 text-[0.65rem] uppercase tracking-wider"
        @click="router.push('/')"
      >
        Back to dashboard
      </button>
      <button
        type="button"
        class="rounded-xl border border-[var(--np-border-subtle)] px-4 py-2.5 text-[0.65rem] font-semibold uppercase tracking-wider text-[var(--np-text-muted)] transition-colors hover:text-[var(--np-text)]"
        @click="router.back()"
      >
        Go back
      </button>
    </div>

    <div
      class="mt-10 flex flex-wrap items-center justify-center gap-x-3 gap-y-1 font-mono text-[0.6rem] uppercase tracking-wider text-[var(--np-text-dim)]"
    >
      <span>Try:</span>
      <router-link
        v-for="link in quickLinks"
        :key="link.to"
        :to="link.to"
        class="np-brand-text transition-opacity hover:opacity-70 hover:underline"
      >
        {{ link.label }}
      </router-link>
    </div>
  </div>
</template>
