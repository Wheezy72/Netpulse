<script setup lang="ts">
import PulsePanel from "../components/PulsePanel.vue";
import TopologyPanel from "../components/TopologyPanel.vue";

interface Props {
  infoMode: "full" | "compact";
}

defineProps<Props>();
</script>

<template>
  <div class="grid gap-4 xl:grid-cols-3">
    <PulsePanel class="xl:col-span-2" />
    <TopologyPanel class="xl:col-span-1" />
  </div>
</template>
