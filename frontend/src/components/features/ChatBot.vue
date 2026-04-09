<script setup lang="ts">
import axios from "axios";
import { ref, nextTick } from "vue";

interface Props {
  theme: "nightshade" | "sysadmin";
}

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

const props = defineProps<Props>();
const emit = defineEmits<{ (e: "close"): void }>();

const message = ref("");
const messages = ref<ChatMessage[]>([]);
const loading = ref(false);
const chatContainer = ref<HTMLElement | null>(null);
const fileInput = ref<HTMLInputElement | null>(null);
const uploading = ref(false);
const suggestions = ref<string[]>([
  "How do I scan my network?",
  "Why is my network slow?",
  "How to secure my network?"
]);

const isNightshade = () => props.theme === "nightshade";

function openFileDialog(): void {
  fileInput.value?.click();
}

async function handleFileUpload(event: Event): Promise<void> {
  const target = event.target as HTMLInputElement;
  const file = target.files?.[0];
  if (!file) return;

  uploading.value = true;
  messages.value.push({ role: "user", content: `Uploading ${file.name}...` });

  await nextTick();
  scrollToBottom();

  try {
    const formData = new FormData();
    formData.append("file", file);

    const { data } = await axios.post<{ response: string; suggestions: string[] }>(
      "/api/chatbot/upload",
      formData,
      {
        headers: { "Content-Type": "multipart/form-data" },
      }
    );

    messages.value[messages.value.length - 1].content = `Uploaded: ${file.name}`;
    messages.value.push({ role: "assistant", content: data.response });
    suggestions.value = data.suggestions || [];
  } catch {
    messages.value.push({
      role: "assistant",
      content: "Sorry, I couldn't process that file. Please try a .pcap, .log, .txt, .json, or .csv file.",
    });
  } finally {
    uploading.value = false;
    target.value = "";
    await nextTick();
    scrollToBottom();
  }
}

async function sendMessage(text?: string): Promise<void> {
  const msg = text || message.value.trim();
  if (!msg || loading.value) return;

  messages.value.push({ role: "user", content: msg });
  message.value = "";
  loading.value = true;

  await nextTick();
  scrollToBottom();

  try {
    const { data } = await axios.post<{ response: string; suggestions: string[] }>(
      "/api/chatbot/chat",
      { message: msg }
    );
    messages.value.push({ role: "assistant", content: data.response });
    suggestions.value = data.suggestions || [];
  } catch {
    messages.value.push({
      role: "assistant",
      content: "Sorry, I couldn't process that request. Please try again.",
    });
  } finally {
    loading.value = false;
    await nextTick();
    scrollToBottom();
  }
}

function scrollToBottom(): void {
  if (chatContainer.value) {
    chatContainer.value.scrollTop = chatContainer.value.scrollHeight;
  }
}

function handleKeydown(e: KeyboardEvent): void {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
}
</script>

<template>
  <div
    class="w-full h-full rounded-xl flex flex-col overflow-hidden shadow-2xl border"
    :class="[
      isNightshade()
        ? 'bg-gray-900/95 border-teal-400/50 backdrop-blur-xl'
        : 'bg-slate-900/95 border-amber-400/50 backdrop-blur-xl'
    ]"
    :style="isNightshade() ? { boxShadow: '0 0 30px rgba(20, 184, 166, 0.3)' } : { boxShadow: '0 0 30px rgba(245, 158, 11, 0.3)' }"
  >
    <header
      class="flex items-center justify-between px-4 py-3 border-b"
      :class="[isNightshade() ? 'border-teal-400/30 bg-black/50' : 'border-amber-400/30 bg-slate-800/50']"
    >
      <div class="flex items-center gap-2">
        <div
          class="w-8 h-8 rounded-lg flex items-center justify-center"
          :class="[isNightshade() ? 'bg-teal-500/20' : 'bg-amber-500/20']"
        >
          <svg
            class="w-4 h-4"
            :class="[isNightshade() ? 'text-teal-400' : 'text-amber-400']"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
          </svg>
        </div>
        <div>
          <h3
            class="text-sm font-semibold"
            :class="[isNightshade() ? 'text-teal-400' : 'text-amber-400']"
            :style="{ fontFamily: isNightshade() ? '\'Orbitron\', sans-serif' : '\'Inter\', system-ui, sans-serif' }"
          >
            AI Assistant
          </h3>
          <p class="text-[0.65rem]" :class="[isNightshade() ? 'text-teal-300/60' : 'text-amber-300/60']">
            Network Operations Help
          </p>
        </div>
      </div>
      <button
        @click="emit('close')"
        class="p-1.5 rounded-lg transition-colors"
        :class="[isNightshade() ? 'hover:bg-teal-400/10 text-teal-400' : 'hover:bg-amber-400/10 text-amber-400']"
      >
        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
        </svg>
      </button>
    </header>

    <div
      ref="chatContainer"
      class="flex-1 overflow-y-auto p-4 space-y-4"
    >
      <div v-if="messages.length === 0" class="text-center py-8">
        <div
          class="w-16 h-16 mx-auto mb-4 rounded-full flex items-center justify-center"
          :class="[isNightshade() ? 'bg-teal-500/10' : 'bg-amber-500/10']"
        >
          <svg
            class="w-8 h-8"
            :class="[isNightshade() ? 'text-teal-400' : 'text-amber-400']"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        </div>
        <p class="text-sm mb-4" :class="[isNightshade() ? 'text-teal-300/80' : 'text-amber-300/80']">
          Ask me about network scanning, troubleshooting, or security best practices.
        </p>
        <div class="space-y-2">
          <button
            v-for="suggestion in suggestions"
            :key="suggestion"
            @click="sendMessage(suggestion)"
            class="block w-full text-left px-3 py-2 rounded-lg text-xs transition-colors"
            :class="[
              isNightshade()
                ? 'bg-teal-500/10 text-teal-300 hover:bg-teal-500/20 border border-teal-400/30'
                : 'bg-amber-500/10 text-amber-300 hover:bg-amber-500/20 border border-amber-400/30'
            ]"
          >
            {{ suggestion }}
          </button>
        </div>
      </div>

      <template v-else>
        <div
          v-for="(msg, idx) in messages"
          :key="idx"
          class="flex"
          :class="[msg.role === 'user' ? 'justify-end' : 'justify-start']"
        >
          <div
            class="max-w-[80%] px-3 py-2 rounded-lg text-sm"
            :class="[
              msg.role === 'user'
                ? isNightshade()
                  ? 'bg-teal-500/20 text-teal-100 border border-teal-400/30'
                  : 'bg-amber-500/20 text-amber-100 border border-amber-400/30'
                : isNightshade()
                  ? 'bg-gray-800 text-gray-100 border border-gray-700'
                  : 'bg-slate-800 text-slate-100 border border-slate-700'
            ]"
          >
            <pre class="whitespace-pre-wrap font-sans text-xs leading-relaxed">{{ msg.content }}</pre>
          </div>
        </div>

        <div v-if="loading" class="flex justify-start">
          <div
            class="px-3 py-2 rounded-lg"
            :class="[isNightshade() ? 'bg-gray-800 border border-gray-700' : 'bg-slate-800 border border-slate-700']"
          >
            <div class="flex items-center gap-1">
              <span class="w-2 h-2 rounded-full animate-bounce" :class="[isNightshade() ? 'bg-teal-400' : 'bg-amber-400']" style="animation-delay: 0ms"></span>
              <span class="w-2 h-2 rounded-full animate-bounce" :class="[isNightshade() ? 'bg-teal-400' : 'bg-amber-400']" style="animation-delay: 150ms"></span>
              <span class="w-2 h-2 rounded-full animate-bounce" :class="[isNightshade() ? 'bg-teal-400' : 'bg-amber-400']" style="animation-delay: 300ms"></span>
            </div>
          </div>
        </div>

        <div v-if="suggestions.length > 0 && !loading" class="pt-2 space-y-1">
          <button
            v-for="suggestion in suggestions"
            :key="suggestion"
            @click="sendMessage(suggestion)"
            class="block w-full text-left px-2 py-1.5 rounded text-[0.7rem] transition-colors"
            :class="[
              isNightshade()
                ? 'text-teal-400/70 hover:bg-teal-500/10'
                : 'text-amber-400/70 hover:bg-amber-500/10'
            ]"
          >
            {{ suggestion }}
          </button>
        </div>
      </template>
    </div>

    <footer class="p-3 border-t" :class="[isNightshade() ? 'border-teal-400/30' : 'border-amber-400/30']">
      <input
        ref="fileInput"
        type="file"
        accept=".pcap,.log,.txt,.json,.csv"
        @change="handleFileUpload"
        class="hidden"
      />
      <div class="flex items-center gap-2">
        <button
          @click="openFileDialog"
          :disabled="uploading || loading"
          type="button"
          class="p-2 rounded-lg transition-colors"
          :class="[
            isNightshade()
              ? 'text-teal-400 hover:bg-teal-500/20 disabled:opacity-40'
              : 'text-amber-400 hover:bg-amber-500/20 disabled:opacity-40'
          ]"
          title="Upload file (pcap, log, txt, json, csv)"
        >
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13" />
          </svg>
        </button>
        <input
          v-model="message"
          @keydown="handleKeydown"
          type="text"
          placeholder="Ask a question..."
          class="flex-1 px-3 py-2 rounded-lg text-sm bg-transparent border outline-none"
          :class="[
            isNightshade()
              ? 'border-teal-400/30 text-teal-100 placeholder-teal-400/40 focus:border-teal-400/60'
              : 'border-amber-400/30 text-amber-100 placeholder-amber-400/40 focus:border-amber-400/60'
          ]"
        />
        <button
          @click="sendMessage()"
          :disabled="loading || !message.trim()"
          class="p-2 rounded-lg transition-colors disabled:opacity-50"
          :class="[
            isNightshade()
              ? 'bg-teal-500/20 text-teal-400 hover:bg-teal-500/30'
              : 'bg-amber-500/20 text-amber-400 hover:bg-amber-500/30'
          ]"
        >
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
          </svg>
        </button>
      </div>
    </footer>
  </div>
</template>
