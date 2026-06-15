<script setup lang="ts">
import { ref, computed } from 'vue'

type Theme = 'nightshade' | 'sysadmin'

interface Props {
  theme: Theme
  isAdmin: boolean
}

const props = defineProps<Props>()
const isNightshade = computed(() => props.theme === 'nightshade')

interface Asset {
  id: number
  ip: string
  hostname: string
  status: 'online' | 'offline'
  lastSeen: string
}

interface AssetDetail extends Asset {
  cpu: number
  memory: string
  ports: { number: number; service: string; state: string }[]
}

const targetRange = ref('')
const selectedAction = ref('find')
const loading = ref(false)
const selectedAsset = ref<AssetDetail | null>(null)

const assets = ref<Asset[]>([
  { id: 1, ip: '10.0.0.12', hostname: 'FW-CORE-01', status: 'online', lastSeen: '1m ago' },
  { id: 2, ip: '10.0.0.45', hostname: 'DB-PROD-02', status: 'online', lastSeen: '2m ago' },
  { id: 3, ip: '10.0.0.88', hostname: '', status: 'offline', lastSeen: '3h ago' },
  { id: 4, ip: '10.0.0.105', hostname: 'APP-WORKER-01', status: 'online', lastSeen: '4m ago' },
  { id: 5, ip: '10.0.0.210', hostname: 'LPT-USER-99', status: 'online', lastSeen: '5m ago' },
])

const sanitizeInput = (e: Event) => {
  const raw = (e.target as HTMLInputElement).value
  targetRange.value = raw.replace(/[^0-9a-fA-F.:/-]/g, '')
}

const executeScan = () => {
  if (!targetRange.value) return

  loading.value = true
  selectedAsset.value = null

  setTimeout(() => {
    loading.value = false
  }, 1800)
}

const selectAsset = (asset: Asset) => {
  if (selectedAsset.value?.id === asset.id) return

  selectedAsset.value = {
    ...asset,
    cpu: Math.floor(Math.random() * 80 + 5),
    memory: (Math.random() * 32 + 4).toFixed(1),
    ports: asset.status === 'online' ? [
      { number: 22, service: 'ssh', state: 'open' },
      { number: 80, service: 'http', state: 'open' },
      { number: 443, service: 'https', state: 'open' }
    ] : []
  }
}
</script>

<template>
  <div class="flex flex-col h-full gap-4">

    <!-- Top bar: scan controls -->
    <div class="np-panel">
      <div class="np-panel-header">
        <div class="flex items-center gap-3">
          <h2 class="np-panel-title">Network Assets</h2>
          <span class="text-xs font-mono" style="color: var(--np-text-dim);">{{ assets.length }} nodes</span>
        </div>
        <div class="flex items-center gap-3">
          <input
            type="text"
            v-model="targetRange"
            @input="sanitizeInput"
            placeholder="Target (e.g., 10.0.0.0/24)"
            class="np-neon-input px-3 py-1.5 text-xs w-48"
          />
          <select v-model="selectedAction" class="np-neon-input pl-3 pr-8 py-1.5 text-xs cursor-pointer tracking-wide">
            <option value="find">Find Connected Devices</option>
            <option value="audit">Audit Services</option>
            <option value="os">Identify OS</option>
          </select>
          <button @click="executeScan" class="np-cyber-btn">
            Run
          </button>
        </div>
      </div>
    </div>

    <!-- Main content: table + optional drawer -->
    <div class="flex-1 flex gap-4 min-h-0">

      <!-- Left: Asset Grid -->
      <div class="np-panel flex flex-col transition-all duration-300 ease-in-out min-w-0" :class="[selectedAsset ? 'w-[70%]' : 'w-full']">

        <!-- Asset Data Grid -->
        <div class="flex-1 overflow-auto custom-scrollbar relative">

          <!-- Skeleton Loader -->
          <div v-if="loading" class="absolute inset-0 p-4 space-y-0 z-10" style="background: color-mix(in srgb, var(--np-bg) 80%, transparent);">
            <div v-for="i in 10" :key="i" class="w-full flex items-center p-3" style="border-bottom: 1px solid var(--np-border-subtle);">
              <div class="skeleton-row h-2 w-2 rounded-full mr-4"></div>
              <div class="skeleton-row h-3 w-32 rounded-sm mr-auto"></div>
              <div class="skeleton-row h-3 w-24 rounded-sm mr-auto"></div>
              <div class="skeleton-row h-3 w-16 rounded-sm"></div>
            </div>
          </div>

          <table class="w-full text-left border-collapse whitespace-nowrap">
            <thead class="sticky top-0 z-10" style="background: color-mix(in srgb, var(--np-bg) 95%, transparent); backdrop-filter: blur(4px);">
              <tr>
                <th class="py-3 pl-4">Status</th>
                <th class="py-3">Address</th>
                <th class="py-3">Hostname</th>
                <th class="py-3">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="asset in assets"
                :key="asset.id"
                @click="selectAsset(asset)"
                class="group cursor-pointer transition-colors"
                :class="{'np-accent-bg': selectedAsset?.id === asset.id}"
                style="border-bottom: 1px solid var(--np-border-subtle);"
              >
                <td class="py-3 pl-4">
                  <div class="flex items-center gap-2">
                    <div
                      class="w-1.5 h-1.5 rounded-full"
                      :style="asset.status === 'online'
                        ? { background: 'var(--np-accent-primary)', boxShadow: '0 0 6px color-mix(in srgb, var(--np-accent-primary) 50%, transparent)' }
                        : { background: 'var(--np-accent-muted)' }"
                    ></div>
                  </div>
                </td>
                <td
                  class="py-3 font-mono text-sm font-medium transition-colors"
                  :style="selectedAsset?.id === asset.id ? { color: 'var(--np-accent-primary)' } : { color: 'var(--np-text)' }"
                >{{ asset.ip }}</td>
                <td class="py-3 text-xs" style="color: var(--np-text-dim);">{{ asset.hostname || '—' }}</td>
                <td class="py-3 text-xs" style="color: var(--np-text-dim); opacity: 0.6;">{{ asset.lastSeen }}</td>
              </tr>
              <tr v-if="!assets.length && !loading">
                <td colspan="4" class="py-8 text-center text-xs font-mono" style="color: var(--np-text-dim);">No assets discovered in target range.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Right: Details Drawer -->
      <Transition name="drawer">
        <div v-if="selectedAsset" class="np-panel w-[30%] flex flex-col shrink-0 min-w-[320px]">
          <div class="np-panel-header">
            <h2 class="np-panel-title">Node Details</h2>
            <button @click="selectedAsset = null" class="transition-colors hover:opacity-80" style="color: var(--np-text-dim);">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M6 18L18 6M6 6l12 12"></path></svg>
            </button>
          </div>

          <div class="flex-1 overflow-auto p-4 space-y-6 custom-scrollbar">

            <!-- Identity -->
            <section class="flex flex-col gap-1">
              <span class="text-[10px] uppercase tracking-widest" style="color: var(--np-text-dim);">Address</span>
              <span class="text-xl font-mono" style="color: var(--np-text);">{{ selectedAsset.ip }}</span>
              <span class="text-sm" style="color: var(--np-text-muted);">{{ selectedAsset.hostname || '—' }}</span>
            </section>

            <!-- Hardware Telemetry -->
            <section>
              <span class="text-[10px] uppercase tracking-widest font-bold mb-2 block" style="color: var(--np-accent-primary); opacity: 0.7;">Hardware Telemetry</span>
              <div class="grid grid-cols-2 gap-3">
                <div class="rounded-lg p-3 flex flex-col gap-1" style="background: color-mix(in srgb, var(--np-bg) 80%, transparent); border: 1px solid var(--np-border);">
                  <span class="text-[10px] uppercase tracking-wide" style="color: var(--np-text-dim);">CPU</span>
                  <span class="text-lg font-mono font-bold" style="color: var(--np-accent-primary);">{{ selectedAsset.cpu }}%</span>
                </div>
                <div class="rounded-lg p-3 flex flex-col gap-1" style="background: color-mix(in srgb, var(--np-bg) 80%, transparent); border: 1px solid var(--np-border);">
                  <span class="text-[10px] uppercase tracking-wide" style="color: var(--np-text-dim);">Memory</span>
                  <span class="text-lg font-mono font-bold" style="color: var(--np-accent-primary);">{{ selectedAsset.memory }} GB</span>
                </div>
              </div>
            </section>

            <!-- Audited Services -->
            <section>
              <span class="text-[10px] uppercase tracking-widest font-bold mb-2 block" style="color: var(--np-accent-primary); opacity: 0.7;">Audited Services</span>
              <div class="space-y-1.5">
                <div v-for="port in selectedAsset.ports" :key="port.number" class="flex justify-between items-center rounded-lg p-2 px-3" style="background: color-mix(in srgb, var(--np-bg) 60%, transparent); border: 1px solid var(--np-border-subtle);">
                  <div class="flex items-center gap-3">
                    <span class="font-mono text-sm font-bold w-10" style="color: var(--np-accent-primary);">{{ port.number }}</span>
                    <span class="text-xs" style="color: var(--np-text-muted);">{{ port.service }}</span>
                  </div>
                  <span class="text-[10px] px-1.5 py-0.5 rounded uppercase tracking-wider font-bold np-accent-bg np-accent-text">{{ port.state }}</span>
                </div>
                <div v-if="!selectedAsset.ports?.length" class="text-xs font-mono py-2" style="color: var(--np-text-dim);">No services audited yet.</div>
              </div>
            </section>

            <!-- RBAC Actions -->
            <section class="pt-6 mt-auto" style="border-top: 1px solid var(--np-border-subtle);">
              <button
                v-if="isAdmin"
                class="w-full bg-transparent border border-rose-500/30 hover:bg-rose-500/10 text-rose-400 font-bold py-2.5 text-xs rounded-lg transition-colors uppercase tracking-widest"
              >
                Isolate Node
              </button>
              <div v-else class="text-[10px] text-center uppercase tracking-widest flex items-center justify-center gap-2 py-2" style="color: var(--np-text-dim);">
                <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
                Admin privileges required
              </div>
            </section>

          </div>
        </div>
      </Transition>

    </div>
  </div>
</template>

<style scoped>
/* Scoped styles have been moved to styles.css for global consistency */
</style>
