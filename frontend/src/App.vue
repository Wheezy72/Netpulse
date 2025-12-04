<script setup lang="ts">
import { onMounted, ref, watch } from "vue";
import Dashboard from "./views/Dashboard.vue";

type Theme = "cyberdeck" | "sysadmin";

/**
 * Reactive theme state. This drives the <body> class and therefore which
 * set of CSS variables (CyberDeck vs SysAdmin Pro) are active.
 */
const theme = ref<Theme>("cyberdeck");

/**
 * Apply the theme by updating the <body> element's class and persisting
 * the selection in localStorage.
 */
function applyTheme(next: Theme): void {
  const body = document.body;
  body.classList.remove("theme-cyberdeck", "theme-sysadmin");
  body.classList.add(`theme-${next}`);
  localStorage.setItem("np-theme", next);
}

onMounted(() => {
  const stored = localStorage.getItem("np-theme") as Theme | null;
  if (stored === "cyberdeck" || stored === "sysadmin") {
    theme.value = stored;
    applyTheme(stored);
  } else {
    applyTheme(theme.value);
  }
});

watch(
  () => theme.value,
  (value) => {
    applyTheme(value);
  }
);

function toggleTheme(): void {
  theme.value = theme.value === "cyberdeck" ? "sysadmin" : "cyberdeck";
}
</script>

<template>
  <div
    class="min-h-screen flex flex-col"
    :style="{
      backgroundColor: 'var(--np-bg)',
      color: 'var(--np-text)'
    }"
  >
    <header
      class="flex items-center justify-between px-6 py-3 border-b"
      :class="[
        theme === 'cyberdeck'
          ? 'border-cyan-400/40 bg-black/40'
          : 'border-slate-200 bg-white/80 backdrop-blur'
      ]"
    >
      <div class="flex items-center gap-3">
        <div
          class="h-8 w-8 rounded-full flex items-center justify-center"
          :class="[
            theme === 'cyberdeck'
              ? 'bg-emerald-400/20 border border-emerald-400/80'
              : 'bg-blue-600/10 border border-blue-600/60'
          ]"
        >
          <span
            class="text-xs font-semibold"
            :class="[theme === 'cyberdeck' ? 'text-emerald-300' : 'text-blue-700']"
          >
            NP
          </span>
        </div>
        <div class="flex flex-col">
          <h1
            class="text-sm font-semibold tracking-[0.18em] uppercase"
            :class="[
              theme === 'cyberdeck' ? 'text-cyan-300 np-text-glow' : 'text-slate-800'
            ]"
          >
            NetPulse Enterprise
          </h1>
          <p
            class="text-xs"
            :class="[theme === 'cyberdeck' ? 'text-cyan-200/70' : 'text-slate-500']"
          >
            Single Pane of Glass · Network Ops &amp; Security Playground
          </p>
        </div>
      </div>

      <div class="flex items-center gap-6">
        <div class="flex flex-col items-end">
          <span
            class="text-xs font-medium"
            :class="[theme === 'cyberdeck' ? 'text-cyan-200' : 'text-slate-700']"
          >
            Theme
          </span>
          <span
            class="text-[0.7rem] uppercase tracking-[0.16em]"
            :class="[theme === 'cyberdeck' ? 'text-cyan-300' : 'text-slate-500']"
          >
            {{ theme === "cyberdeck" ? "CyberDeck" : "SysAdmin Pro" }}
          </span>
        </div>

        <!--
          Theme toggle switch:
          - CyberDeck: neon hacker aesthetic.
          - SysAdmin Pro: clean, high-visibility layout.
          The switch updates the global body class so child components can
          rely on CSS variables instead of custom logic.
        -->
        <button
          type="button"
          @click="toggleTheme"
          class="relative inline-flex h-8 w-16 items-center rounded-full border transition
                 focus:outline-none focus:ring-2 focus:ring-offset-2"
          :class="[
            theme === 'cyberdeck'
              ? 'border-cyan-400 bg-black/70 focus:ring-cyan-400'
              : 'border-slate-300 bg-slate-100 focus:ring-blue-500'
          ]"
        >
          <span
            class="inline-flex h-6 w-6 transform items-center justify-center rounded-full text-[0.6rem] font-semibold transition"
            :class="[
              theme === 'cyberdeck'
                ? 'translate-x-1 bg-cyan-400 text-black shadow-[0_0_12px_rgba(34,211,238,0.9)]'
                : 'translate-x-9 bg-blue-600 text-white shadow-sm'
            ]"
          >
            {{ theme === "cyberdeck" ? "CD" : "SA" }}
          </span>
        </button>
      </div>
    </header>

    <main class="flex-1 px-4 py-4 md:px-6 md:py-6">
      <Dashboard />
    </main>
  </div>
</template>ript setup lang="ts"&gt;
import { onMounted, ref, watch } from "vue";
import Dashboard from "./views/Dashboard.vue";

type Theme = "cyberdeck" | "sysadmin";

/**
 * Reactive theme state. This drives the &lt;body&gt; class and therefore which
 * set of CSS variables (CyberDeck vs SysAdmin Pro) are active.
 */
const theme = ref&lt;Theme&gt;("cyberdeck");

/**
 * Apply the theme by updating the &lt;body&gt; element's class and persisting
 * the selection in localStorage.
 */
function applyTheme(next: Theme): void {
  const body = document.body;
  body.classList.remove("theme-cyberdeck", "theme-sysadmin");
  body.classList.add(`theme-${next}`);
  localStorage.setItem("np-theme", next);
}

onMounted(() =&gt; {
  const stored = localStorage.getItem("np-theme") as Theme | null;
  if (stored === "cyberdeck" || stored === "sysadmin") {
    theme.value = stored;
    applyTheme(stored);
  } else {
    applyTheme(theme.value);
  }
});

watch(
  () =&gt; theme.value,
  (value) =&gt; {
    applyTheme(value);
  }
);

function toggleTheme(): void {
  theme.value = theme.value === "cyberdeck" ? "sysadmin" : "cyberdeck";
}
&lt;/script&gt;

&lt;template&gt;
  &lt;div
    class="min-h-screen flex flex-col"
    :style="{
      backgroundColor: 'var(--np-bg)',
      color: 'var(--np-text)'
    }"
  &gt;
    &lt;header
      class="flex items-center justify-between px-6 py-3 border-b"
      :class="[
        theme === 'cyberdeck'
          ? 'border-cyan-400/40 bg-black/40'
          : 'border-slate-200 bg-white/80 backdrop-blur'
      ]"
    &gt;
      &lt;div class="flex items-center gap-3"&gt;
        &lt;div
          class="h-8 w-8 rounded-full flex items-center justify-center"
          :class="[
            theme === 'cyberdeck'
              ? 'bg-emerald-400/20 border border-emerald-400/80'
              : 'bg-blue-600/10 border border-blue-600/60'
          ]"
        &gt;
          &lt;span
            class="text-xs font-semibold"
            :class="[theme === 'cyberdeck' ? 'text-emerald-300' : 'text-blue-700']"
          &gt;
            NP
          &lt;/span&gt;
        &lt;/div&gt;
        &lt;div class="flex flex-col"&gt;
          &lt;h1
            class="text-sm font-semibold tracking-[0.18em] uppercase"
            :class="[
              theme === 'cyberdeck' ? 'text-cyan-300 np-text-glow' : 'text-slate-800'
            ]"
          &gt;
            NetPulse Enterprise
          &lt;/h1&gt;
          &lt;p
            class="text-xs"
            :class="[theme === 'cyberdeck' ? 'text-cyan-200/70' : 'text-slate-500']"
          &gt;
            Single Pane of Glass · Network Ops &amp; Security Playground
          &lt;/p&gt;
        &lt;/div&gt;
      &lt;/div&gt;

      &lt;div class="flex items-center gap-6"&gt;
        &lt;div class="flex flex-col items-end"&gt;
          &lt;span
            class="text-xs font-medium"
            :class="[theme === 'cyberdeck' ? 'text-cyan-200' : 'text-slate-700']"
          &gt;
            Theme
          &lt;/span&gt;
          &lt;span
            class="text-[0.7rem] uppercase tracking-[0.16em]"
            :class="[theme === 'cyberdeck' ? 'text-cyan-300' : 'text-slate-500']"
          &gt;
            {{ theme === "cyberdeck" ? "CyberDeck" : "SysAdmin Pro" }}
          &lt;/span&gt;
        &lt;/div&gt>

        <!--
          Theme toggle switch:
          - CyberDeck: neon hacker aesthetic.
          - SysAdmin Pro: clean, high-visibility layout.
          The switch updates the global body class so child components can
          rely on CSS variables instead of custom logic.
        -->
        &lt;button
          type="button"
          @click="toggleTheme"
          class="relative inline-flex h-8 w-16 items-center rounded-full border transition
                 focus:outline-none focus:ring-2 focus:ring-offset-2"
          :class="[
            theme === 'cyberdeck'
              ? 'border-cyan-400 bg-black/70 focus:ring-cyan-400'
              : 'border-slate-300 bg-slate-100 focus:ring-blue-500'
          ]"
        &gt;
          &lt;span
            class="inline-flex h-6 w-6 transform items-center justify-center rounded-full text-[0.6rem] font-semibold transition"
            :class="[
              theme === 'cyberdeck'
                ? 'translate-x-1 bg-cyan-400 text-black shadow-[0_0_12px_rgba(34,211,238,0.9)]'
                : 'translate-x-9 bg-blue-600 text-white shadow-sm'
            ]"
          &gt;
            {{ theme === "cyberdeck" ? "CD" : "SA" }}
          &lt;/span&gt;
        &lt;/button&gt;
      &lt;/div&gt;
    &lt;/header&gt;

    &lt;main class="flex-1 px-4 py-4 md:px-6 md:py-6"&gt;
      &lt;Dashboard /&gt;
    &lt;/main&gt;
  &lt;/div&gt;
&lt;/template&gt;