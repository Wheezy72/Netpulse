<script setup lang="ts">
import { ref, watch } from "vue";
import type { Component } from "vue";
import { CircleCheck, CircleX, Info, TriangleAlert, X } from "lucide-vue-next";

interface Props {
  theme: "nightshade" | "sysadmin";
}

export interface ToastMessage {
  id: number;
  type: "success" | "error" | "warning" | "info";
  message: string;
  duration?: number;
}

const props = defineProps<Props>();
const toasts = ref<ToastMessage[]>([]);
let toastId = 0;

function show(type: ToastMessage["type"], message: string, duration = 4000): void {
  const id = ++toastId;
  toasts.value.push({ id, type, message, duration });

  if (duration > 0) {
    setTimeout(() => remove(id), duration);
  }
}

function remove(id: number): void {
  toasts.value = toasts.value.filter((t) => t.id !== id);
}

function success(message: string, duration?: number): void {
  show("success", message, duration);
}

function error(message: string, duration?: number): void {
  show("error", message, duration);
}

function warning(message: string, duration?: number): void {
  show("warning", message, duration);
}

function info(message: string, duration?: number): void {
  show("info", message, duration);
}

defineExpose({ show, success, error, warning, info });

const isNightshade = () => props.theme === "nightshade";

function getIcon(type: ToastMessage["type"]): Component {
  switch (type) {
    case "success":
      return CircleCheck;
    case "error":
      return CircleX;
    case "warning":
      return TriangleAlert;
    case "info":
    default:
      return Info;
  }
}

function getColors(type: ToastMessage["type"]): { bg: string; border: string; text: string; icon: string } {
  // Light theme needs dark text on a pale surface; the old dark-theme
  // palette (e.g. text-green-100 on white) was effectively invisible.
  const dark = isNightshade();
  switch (type) {
    case "success":
      return dark
        ? { bg: "bg-emerald-500/15", border: "border-emerald-400/40", text: "text-emerald-100", icon: "text-emerald-400" }
        : { bg: "bg-emerald-50", border: "border-emerald-600/45", text: "text-emerald-900", icon: "text-emerald-700" };
    case "error":
      return dark
        ? { bg: "bg-red-500/15", border: "border-red-400/40", text: "text-red-100", icon: "text-red-400" }
        : { bg: "bg-red-50", border: "border-red-600/45", text: "text-red-900", icon: "text-red-700" };
    case "warning":
      return dark
        ? { bg: "bg-amber-500/15", border: "border-amber-400/40", text: "text-amber-100", icon: "text-amber-400" }
        : { bg: "bg-amber-50", border: "border-amber-700/45", text: "text-amber-900", icon: "text-amber-700" };
    case "info":
    default:
      return dark
        ? { bg: "bg-sky-500/15", border: "border-sky-400/35", text: "text-sky-100", icon: "text-sky-400" }
        : { bg: "bg-sky-50", border: "border-sky-700/45", text: "text-sky-900", icon: "text-sky-700" };
  }
}
</script>

<template>
  <div class="fixed top-4 right-4 z-[60] space-y-2 max-w-sm">
    <TransitionGroup name="toast">
      <div
        v-for="toast in toasts"
        :key="toast.id"
        class="flex items-start gap-3 px-4 py-3 rounded-lg border backdrop-blur-lg shadow-lg"
        :class="[getColors(toast.type).bg, getColors(toast.type).border]"
      >
        <component
          :is="getIcon(toast.type)"
          class="w-5 h-5 flex-shrink-0 mt-0.5"
          :class="getColors(toast.type).icon"
          :stroke-width="1.7"
        />
        <p class="text-sm flex-1" :class="getColors(toast.type).text">
          {{ toast.message }}
        </p>
        <button
          @click="remove(toast.id)"
          class="p-0.5 rounded transition-colors opacity-70 hover:opacity-100"
          :class="getColors(toast.type).icon"
          aria-label="Dismiss"
          title="Dismiss"
        >
          <X class="w-4 h-4" :stroke-width="1.7" />
        </button>
      </div>
    </TransitionGroup>
  </div>
</template>

<style scoped>
.toast-enter-active {
  transition: opacity 0.3s ease-out, transform 0.3s ease-out;
}

.toast-leave-active {
  transition: opacity 0.2s ease-in, transform 0.2s ease-in;
}

.toast-enter-from {
  opacity: 0;
  transform: translateX(100%);
}

.toast-leave-to {
  opacity: 0;
  transform: translateX(100%);
}
</style>
