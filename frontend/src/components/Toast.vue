<script setup lang="ts">
import { ref, watch } from "vue";

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

function getIcon(type: ToastMessage["type"]): string {
  switch (type) {
    case "success":
      return "M5 13l4 4L19 7";
    case "error":
      return "M6 18L18 6M6 6l12 12";
    case "warning":
      return "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z";
    case "info":
    default:
      return "M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z";
  }
}

function getColors(type: ToastMessage["type"]): { bg: string; border: string; text: string; icon: string } {
  const cyber = isNightshade();
  switch (type) {
    case "success":
      return {
        bg: cyber ? "bg-emerald-500/20" : "bg-green-500/20",
        border: cyber ? "border-emerald-400/50" : "border-green-400/50",
        text: cyber ? "text-emerald-100" : "text-green-100",
        icon: cyber ? "text-emerald-400" : "text-green-400",
      };
    case "error":
      return {
        bg: "bg-red-500/20",
        border: "border-red-400/50",
        text: "text-red-100",
        icon: "text-red-400",
      };
    case "warning":
      return {
        bg: "bg-amber-500/20",
        border: "border-amber-400/50",
        text: "text-amber-100",
        icon: "text-amber-400",
      };
    case "info":
    default:
      return {
        bg: cyber ? "bg-teal-500/20" : "bg-amber-500/20",
        border: cyber ? "border-teal-400/50" : "border-amber-400/50",
        text: cyber ? "text-teal-100" : "text-amber-100",
        icon: cyber ? "text-teal-400" : "text-amber-400",
      };
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
        <svg
          class="w-5 h-5 flex-shrink-0 mt-0.5"
          :class="getColors(toast.type).icon"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" :d="getIcon(toast.type)" />
        </svg>
        <p class="text-sm flex-1" :class="getColors(toast.type).text">
          {{ toast.message }}
        </p>
        <button
          @click="remove(toast.id)"
          class="p-0.5 rounded transition-colors opacity-70 hover:opacity-100"
          :class="getColors(toast.type).icon"
        >
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>
    </TransitionGroup>
  </div>
</template>

<style scoped>
.toast-enter-active {
  transition: all 0.3s ease-out;
}

.toast-leave-active {
  transition: all 0.2s ease-in;
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
