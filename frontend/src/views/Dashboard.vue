<template>
  <div class="cyber-canvas absolute inset-0 overflow-hidden text-gray-300 font-sans flex flex-col">
    <!-- Ambient Background Animation -->
    <div class="ambient-glow absolute inset-0 pointer-events-none z-0"></div>

    <!-- Header (Minimal, non-bombastic) -->
    <header class="relative z-10 w-full p-4 flex items-center justify-between border-b border-white/5 bg-black/40">
      <div class="flex items-center gap-3">
        <div class="w-6 h-6 border border-cyan-400/50 rounded-sm flex items-center justify-center font-bold text-cyan-400 text-xs">
          NP
        </div>
        <h1 class="text-xs font-bold tracking-widest text-white uppercase">Netpulse</h1>
      </div>
      <div class="flex items-center gap-4 text-xs font-mono">
        <span class="text-gray-400">System Online</span>
        <span class="text-gray-600">|</span>
        <span class="text-green-400 flex items-center gap-1.5">
          <div class="w-1.5 h-1.5 rounded-full bg-green-400"></div> Active
        </span>
      </div>
    </header>

    <!-- Workspace -->
    <main class="relative z-10 flex-1 flex gap-4 p-4 min-h-0">
      
      <!-- Left: Asset Grid (70% or 100%) -->
      <div class="panel flex flex-col transition-all duration-300 ease-in-out min-w-0" :class="[selectedAsset ? 'w-[70%]' : 'w-full']">
        
        <!-- Table Header & Consolidated Nmap Controls -->
        <div class="p-3 border-b border-white/10 flex flex-wrap gap-4 justify-between items-center bg-black/40 shrink-0">
          <div class="flex items-center gap-3">
            <h2 class="text-sm font-bold uppercase tracking-widest text-cyan-400">Network Assets</h2>
            <span class="text-xs text-gray-500 font-mono">{{ assets.length }} nodes</span>
          </div>
          
          <div class="flex items-center gap-3">
            <input 
              type="text" 
              v-model="targetRange"
              @input="sanitizeInput"
              placeholder="Target (e.g., 10.0.0.0/24)"
              class="bg-black/80 border border-gray-700 focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 rounded-sm px-3 py-1.5 text-xs w-48 outline-none font-mono text-gray-200 transition-colors placeholder-gray-600"
            />
            <div class="relative">
              <select v-model="selectedAction" class="appearance-none bg-black/80 border border-gray-700 hover:border-fuchsia-500 rounded-sm pl-3 pr-8 py-1.5 text-xs outline-none transition-colors cursor-pointer text-gray-200 tracking-wide">
                <option value="find">Find Connected Devices</option>
                <option value="audit">Audit Services</option>
                <option value="os">Identify OS</option>
              </select>
              <div class="absolute inset-y-0 right-2 flex items-center pointer-events-none">
                <svg class="w-3 h-3 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="square" stroke-linejoin="miter" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
              </div>
            </div>
            <button @click="executeScan" class="bg-cyan-500/10 border border-cyan-500/50 hover:bg-cyan-500/20 text-cyan-400 uppercase tracking-wider font-bold px-4 py-1.5 text-xs rounded-sm transition-colors">
              Run
            </button>
          </div>
        </div>

        <!-- Asset Data Grid -->
        <div class="flex-1 overflow-auto custom-scrollbar relative">
          
          <!-- Skeleton Loader -->
          <div v-if="loading" class="absolute inset-0 p-4 space-y-0 bg-black/20 z-10">
            <div v-for="i in 10" :key="i" class="w-full flex items-center p-3 border-b border-white/5">
              <div class="skeleton-row h-2 w-2 rounded-full mr-4"></div>
              <div class="skeleton-row h-3 w-32 rounded-sm mr-auto"></div>
              <div class="skeleton-row h-3 w-24 rounded-sm mr-auto"></div>
              <div class="skeleton-row h-3 w-16 rounded-sm"></div>
            </div>
          </div>
          
          <table class="w-full text-left border-collapse whitespace-nowrap">
            <thead class="sticky top-0 bg-black/80 backdrop-blur-sm z-10">
              <tr class="text-[10px] uppercase tracking-widest text-gray-500 border-b border-white/5">
                <th class="py-3 pl-4 font-bold">Status</th>
                <th class="py-3 font-bold">Address</th>
                <th class="py-3 font-bold">Hostname</th>
                <th class="py-3 font-bold">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              <tr 
                v-for="asset in assets" 
                :key="asset.id" 
                @click="selectAsset(asset)"
                class="group cursor-pointer border-b border-white/5 hover:bg-white/[0.02] transition-colors"
                :class="{'bg-white/[0.04]': selectedAsset?.id === asset.id}"
              >
                <td class="py-3 pl-4">
                  <div class="flex items-center gap-2">
                    <div class="w-1.5 h-1.5 rounded-full shadow-[0_0_5px_currentColor]" :class="asset.status === 'online' ? 'bg-cyan-400 text-cyan-400' : 'bg-gray-600 text-gray-600'"></div>
                  </div>
                </td>
                <td class="py-3 font-mono text-sm text-gray-300 font-medium group-hover:text-cyan-400 transition-colors">{{ asset.ip }}</td>
                <td class="py-3 text-xs text-gray-400">{{ asset.hostname || '—' }}</td>
                <td class="py-3 text-xs text-gray-500">{{ asset.lastSeen }}</td>
              </tr>
              <tr v-if="!assets.length && !loading">
                <td colspan="4" class="py-8 text-center text-xs text-gray-600 font-mono">No assets discovered in target range.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Right: Details Drawer (30%) using Amber telemetry theme -->
      <Transition name="drawer">
        <div v-if="selectedAsset" class="panel panel-amber w-[30%] flex flex-col shrink-0 min-w-[320px]">
          <div class="p-4 border-b border-amber-500/20 flex justify-between items-center bg-black/40 shrink-0">
            <h2 class="text-sm font-bold uppercase tracking-widest text-amber-500">Node Details</h2>
            <button @click="selectedAsset = null" class="text-gray-500 hover:text-amber-400 transition-colors">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="square" stroke-linejoin="miter" stroke-width="1.5" d="M6 18L18 6M6 6l12 12"></path></svg>
            </button>
          </div>
          
          <div class="flex-1 overflow-auto p-4 space-y-6 custom-scrollbar-amber">
            
            <!-- Identity -->
            <section class="flex flex-col gap-1">
              <span class="text-[10px] text-gray-500 uppercase tracking-widest">Address</span>
              <span class="text-xl font-mono text-white">{{ selectedAsset.ip }}</span>
              <span class="text-sm text-gray-400">{{ selectedAsset.hostname || '—' }}</span>
            </section>

            <!-- Hardware Telemetry -->
            <section>
              <span class="text-[10px] text-amber-500/70 uppercase tracking-widest font-bold mb-2 block">Hardware Telemetry</span>
              <div class="grid grid-cols-2 gap-3">
                <div class="bg-black/50 border border-amber-500/20 rounded-sm p-3 flex flex-col gap-1">
                  <span class="text-[10px] text-gray-500 uppercase tracking-wide">CPU</span>
                  <span class="text-lg font-mono text-amber-400 font-bold">{{ selectedAsset.cpu || '—' }}%</span>
                </div>
                <div class="bg-black/50 border border-amber-500/20 rounded-sm p-3 flex flex-col gap-1">
                  <span class="text-[10px] text-gray-500 uppercase tracking-wide">Memory</span>
                  <span class="text-lg font-mono text-amber-400 font-bold">{{ selectedAsset.memory || '—' }} GB</span>
                </div>
              </div>
            </section>

            <!-- Audited Services -->
            <section>
              <span class="text-[10px] text-amber-500/70 uppercase tracking-widest font-bold mb-2 block">Audited Services</span>
              <div class="space-y-1.5">
                <div v-for="port in selectedAsset.ports" :key="port.number" class="flex justify-between items-center bg-black/30 border border-amber-500/10 rounded-sm p-2 px-3">
                  <div class="flex items-center gap-3">
                    <span class="font-mono text-amber-500 text-sm font-bold w-10">{{ port.number }}</span>
                    <span class="text-xs text-gray-300">{{ port.service }}</span>
                  </div>
                  <span class="text-[10px] px-1.5 py-0.5 rounded-sm bg-amber-500/10 text-amber-500 uppercase tracking-wider font-bold">{{ port.state }}</span>
                </div>
                <div v-if="!selectedAsset.ports?.length" class="text-xs text-gray-600 font-mono py-2">No services audited yet.</div>
              </div>
            </section>

            <!-- RBAC Actions -->
            <section class="pt-6 mt-auto border-t border-amber-500/10">
              <button 
                v-if="userRole === 'admin'"
                class="w-full bg-transparent border border-red-500/40 hover:bg-red-500/10 text-red-500 font-bold py-2.5 text-xs rounded-sm transition-colors uppercase tracking-widest"
              >
                Isolate Node
              </button>
              <div v-else class="text-[10px] text-center text-gray-600 uppercase tracking-widest flex items-center justify-center gap-2 py-2">
                <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="square" stroke-linejoin="miter" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
                Admin privileges required
              </div>
            </section>

          </div>
        </div>
      </Transition>

    </main>
  </div>
</template>

<script setup>
import { ref } from 'vue'

// Role-Based Access Control Mock
const userRole = ref('admin') // Switch to 'operator' to see RBAC in action

const targetRange = ref('')
const selectedAction = ref('find')
const loading = ref(false)
const selectedAsset = ref(null)

const assets = ref([
  { id: 1, ip: '10.0.0.12', hostname: 'FW-CORE-01', status: 'online', lastSeen: '1m ago' },
  { id: 2, ip: '10.0.0.45', hostname: 'DB-PROD-02', status: 'online', lastSeen: '2m ago' },
  { id: 3, ip: '10.0.0.88', hostname: '', status: 'offline', lastSeen: '3h ago' },
  { id: 4, ip: '10.0.0.105', hostname: 'APP-WORKER-01', status: 'online', lastSeen: '4m ago' },
  { id: 5, ip: '10.0.0.210', hostname: 'LPT-USER-99', status: 'online', lastSeen: '5m ago' },
])

// Input Security: Sanitization logic for Nmap target ranges
const sanitizeInput = (e) => {
  const raw = e.target.value
  // Allow only valid IPv4/IPv6, CIDR notation, and hyphens
  targetRange.value = raw.replace(/[^0-9a-fA-F\.\:\/\-]/g, '')
}

const executeScan = () => {
  if (!targetRange.value) return
  
  loading.value = true
  selectedAsset.value = null
  
  // Simulate network request delay for sophisticated skeleton shimmer
  setTimeout(() => {
    loading.value = false
    // In a real scenario, this would populate `assets.value` from the API response
  }, 1800)
}

const selectAsset = (asset) => {
  // If clicking the same row, optionally toggle it off or keep open
  if (selectedAsset.value?.id === asset.id) return

  // Mock fetching detailed telemetry data
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

<style scoped>
/* Scoped styles have been moved to styles.css for global consistency */
</style>
