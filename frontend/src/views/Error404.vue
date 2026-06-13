<script setup lang="ts">
import { useRouter } from "vue-router";
const router = useRouter();
</script>

<template>
  <div class="min-h-screen flex flex-col items-center justify-center relative bg-[#09090b]">
    <h1 class="text-6xl font-bold font-mono mb-4 text-slate-300">404</h1>
    <p class="text-slate-500 mb-8 font-mono">Signal lost. Sector not found.</p>
    <button @click="router.push('/')" class="px-6 py-2 rounded-lg border border-slate-700 hover:bg-slate-800 transition-colors font-mono text-sm text-slate-300">
      Return to Operations
    </button>
  </div>
</template>
