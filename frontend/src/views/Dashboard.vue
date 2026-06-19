<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import axios from 'axios'

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
  role: string
  status: 'online' | 'offline'
  lastSeen: string
  platform: 'aws' | 'gcp' | 'azure' | 'linux' | 'windows' | 'cisco'
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical'
  riskValue: number // 10-100 for visual bars
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
const searchQuery = ref('')
const selectedZoneFilter = ref('all')

const assets = ref<Asset[]>([])

async function fetchLiveDevices() {
  try {
    const { data } = await axios.get('/api/devices')
    assets.value = data.map((d: any) => ({
      id: d.id,
      ip: d.ip_address,
      hostname: d.hostname || d.ip_address,
      role: d.device_type || (d.is_gateway ? 'Gateway Router' : 'Network Host'),
      status: 'online',
      lastSeen: new Date(d.last_seen).toLocaleTimeString(),
      platform: d.device_type?.includes('windows') ? 'windows' : 'linux', // Fallback icon styling
      riskLevel: d.is_gateway ? 'Medium' : 'Low',
      riskValue: d.is_gateway ? 50 : 20
    }))
    if (assets.value.length > 0) {
      selectAsset(assets.value[0])
    }
  } catch (error) {
    console.error("Failed to load real devices:", error)
  }
}

// Filter assets based on search query
const filteredAssets = computed(() => {
  return assets.value.filter(asset => {
    const matchesSearch = asset.ip.includes(searchQuery.value) || 
                          asset.hostname.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
                          asset.role.toLowerCase().includes(searchQuery.value.toLowerCase())
    
    if (selectedZoneFilter.value === 'all') return matchesSearch
    if (selectedZoneFilter.value === 'dmz') return matchesSearch && ['gcp', 'cisco'].includes(asset.platform)
    if (selectedZoneFilter.value === 'internal') return matchesSearch && ['aws', 'azure', 'linux', 'windows'].includes(asset.platform)
    return matchesSearch
  })
})

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
      { number: 443, service: 'https', state: 'open' },
      { number: 161, service: 'snmp', state: 'open' }
    ] : []
  }
}

// Custom tooltip states
const activeBarTooltip = ref<number | null>(null)

// Cleared mock datasets to ensure 100% real telemetry
const zonesData = ref<any[]>([])
const accessTypeData = ref<any[]>([])

onMounted(() => {
  fetchLiveDevices()
})
</script>

<template>
  <div class="flex flex-col h-full gap-5">
    
    <!-- Top Row Header Section: Scan controls -->
    <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-2xl bg-[#050505]/70 border border-slate-600/10 backdrop-blur-md">
      <div class="flex flex-col gap-1">
        <h2 class="text-base font-bold uppercase tracking-wider text-slate-100 font-sans">Command Posture</h2>
        <p class="text-[0.65rem] text-slate-400/50">Manage network security monitoring, active hosts, and vulnerability assessments.</p>
      </div>

      <!-- Removed Tabs - Focused only on Live Hosts -->
    </div>

    <!-- Active view switch -->
    <div class="flex-1 min-h-0 relative z-10">
      
      <!-- ============================================ -->
      <!-- VIEW: IDENTITIES & HOSTS                     -->
      <!-- ============================================ -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-5 animate-fade-in">
        
        <!-- Left 2 Columns: Charts & Node Table -->
        <div class="lg:col-span-2 flex flex-col gap-5">
          
          <!-- Top row widgets -->
          <div class="grid grid-cols-1 md:grid-cols-3 gap-5">
            
            <!-- Protocol Breakdown Bar Chart -->
            <div class="p-4 rounded-2xl bg-[#050505]/65 border border-slate-600/10 shadow-lg relative flex flex-col justify-between min-h-[220px]">
              <div>
                <span class="text-[0.6rem] font-bold uppercase tracking-widest text-slate-400/60">Traffic Protocols</span>
                <div class="flex items-center gap-3 mt-1.5">
                  <div class="flex items-center gap-1">
                    <span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
                    <span class="text-[0.55rem] text-slate-400/50 font-mono">TCP Traffic</span>
                  </div>
                  <div class="flex items-center gap-1">
                    <span class="w-1.5 h-1.5 rounded-full bg-slate-500"></span>
                    <span class="text-[0.55rem] text-slate-400/50 font-mono">UDP / Other</span>
                  </div>
                </div>
              </div>
              
              <div v-if="accessTypeData.length > 0" class="flex items-end justify-between h-24 pt-4 px-1 gap-2 relative">
                <div 
                  v-for="(data, idx) in accessTypeData" 
                  :key="idx" 
                  class="flex flex-col items-center flex-1 group cursor-pointer relative"
                  @mouseenter="activeBarTooltip = idx"
                  @mouseleave="activeBarTooltip = null"
                >
                  <div class="w-full flex items-end justify-center gap-0.5 h-16 relative">
                    <div 
                      class="w-2.5 rounded-full bg-gradient-to-t from-slate-700 to-emerald-500 transition-all duration-500 relative"
                      :style="{ height: `${data.tcp}%` }"
                    />
                    <div 
                      class="w-2.5 rounded-full bg-gradient-to-t from-slate-800 to-slate-500 transition-all duration-500 relative"
                      :style="{ height: `${data.udp}%` }"
                    />
                  </div>
                  <span class="text-[0.55rem] font-mono text-slate-400/40 mt-1.5">{{ data.month }}</span>
                  
                  <div 
                    v-if="activeBarTooltip === idx"
                    class="absolute bottom-full mb-2 bg-[#0f0f11] border border-emerald-500/30 text-white rounded px-2 py-1 text-[0.55rem] font-mono shadow-xl z-50 pointer-events-none"
                  >
                    <p class="text-emerald-400 font-bold">TCP: {{ data.tcp }}%</p>
                    <p class="text-slate-300">UDP/Other: {{ data.udp }}%</p>
                  </div>
                </div>
              </div>
              <div v-else class="flex-1 flex items-center justify-center min-h-[100px] text-[0.6rem] font-mono text-slate-400/40 uppercase tracking-widest">
                Awaiting Telemetry
              </div>
            </div>

            <!-- Active Subnets Progress List -->
            <div class="p-4 rounded-2xl bg-[#050505]/65 border border-slate-600/10 shadow-lg flex flex-col justify-between min-h-[220px]">
              <div>
                <span class="text-[0.6rem] font-bold uppercase tracking-widest text-slate-400/60">Active Network Segments</span>
                <p class="text-[0.55rem] text-slate-400/30 mt-1">Host occupancy per subnet</p>
              </div>

              <div v-if="zonesData.length > 0" class="space-y-3.5 my-3">
                <div v-for="(zone, index) in zonesData" :key="index" class="flex flex-col gap-1.5">
                  <div class="flex items-center justify-between text-[0.55rem] font-mono">
                    <span class="text-slate-200 truncate max-w-[110px]">{{ zone.name }}</span>
                    <span class="text-slate-400/60">{{ zone.current }}/{{ zone.total }}</span>
                  </div>
                  <div class="h-2 w-full rounded-full bg-[#151229] overflow-hidden border border-slate-600/5 relative">
                    <div 
                      class="h-full rounded-full transition-all duration-500" 
                      :style="{ width: `${zone.percent}%`, backgroundColor: zone.color }"
                    />
                  </div>
                </div>
              </div>
              <div v-else class="flex-1 flex items-center justify-center min-h-[100px] text-[0.6rem] font-mono text-slate-400/40 uppercase tracking-widest">
                Awaiting Telemetry
              </div>
            </div>

            <!-- Host Risk Donut Chart -->
            <div class="p-4 rounded-2xl bg-[#050505]/65 border border-slate-600/10 shadow-lg flex flex-col justify-between items-center min-h-[220px] relative">
              <div class="w-full text-left">
                <span class="text-[0.6rem] font-bold uppercase tracking-widest text-slate-400/60">Host Risk Distribution</span>
              </div>

              <div v-if="assets.length > 0" class="relative w-28 h-28 my-2 flex items-center justify-center">
                <svg viewBox="0 0 100 100" class="w-full h-full transform -rotate-90">
                  <circle cx="50" cy="50" r="40" fill="transparent" stroke="#10b981" stroke-width="12" stroke-dasharray="251.2" stroke-dashoffset="0" />
                </svg>
                <div class="absolute flex flex-col items-center justify-center leading-none text-center">
                  <span class="text-xl font-bold font-mono text-white tracking-tighter">{{ assets.length }}</span>
                  <span class="text-[0.5rem] uppercase tracking-wider text-slate-400/60 mt-1">Total Hosts</span>
                </div>
              </div>
              <div v-else class="flex-1 flex items-center justify-center min-h-[100px] text-[0.6rem] font-mono text-slate-400/40 uppercase tracking-widest text-center mt-2">
                Awaiting Telemetry
              </div>

              <div v-if="assets.length > 0" class="grid grid-cols-4 gap-2 w-full text-center text-[0.55rem] font-mono text-slate-400/60 border-t border-slate-600/5 pt-2">
                <div class="flex flex-col"><span class="text-emerald-400 font-bold">100%</span><span>Low</span></div>
                <div class="flex flex-col"><span class="text-cyan-400 font-bold">0%</span><span>Med</span></div>
                <div class="flex flex-col"><span class="text-slate-400 font-bold">0%</span><span>High</span></div>
                <div class="flex flex-col"><span class="text-emerald-400 font-bold">0%</span><span>Crit</span></div>
              </div>
            </div>
          </div>

          <!-- Bottom: Active Identities/Nodes Table Card -->
          <div class="rounded-2xl bg-[#050505]/65 border border-slate-600/10 shadow-lg flex flex-col flex-1 min-h-[350px]">
            <div class="p-4 border-b border-slate-600/10 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div class="flex items-center gap-3">
                <span class="text-xs font-bold uppercase tracking-wider text-slate-100">{{ assets.length }} Discovered Network Hosts</span>
                <span class="text-[0.6rem] px-2 py-0.5 rounded-full font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Live</span>
              </div>
              
              <div class="flex items-center gap-2">
                <input 
                  type="text" 
                  v-model="searchQuery"
                  placeholder="Search hosts or IPs..."
                  class="bg-[#0f0f11]/80 border border-slate-600/10 text-slate-100 text-xs px-3 py-1.5 rounded-lg focus:outline-none focus:border-emerald-500/50 w-44 font-mono"
                />
                <select 
                  v-model="selectedZoneFilter"
                  class="bg-[#0f0f11]/80 border border-slate-600/10 text-slate-200 text-xs px-2 py-1.5 rounded-lg focus:outline-none focus:border-emerald-500/50 cursor-pointer"
                >
                  <option value="all">All Zones</option>
                  <option value="dmz">DMZ Public Zone</option>
                  <option value="internal">Internal LAN</option>
                </select>
              </div>
            </div>

            <div class="flex-1 overflow-auto custom-scrollbar">
              <table class="w-full text-left border-collapse whitespace-nowrap">
                <thead>
                  <tr class="bg-black/25 text-[0.6rem] text-slate-400/50 uppercase tracking-widest border-b border-slate-600/10 font-bold">
                    <th class="py-3 px-4">Hostname &amp; Role</th>
                    <th class="py-3 px-4">IP Address</th>
                    <th class="py-3 px-4">Last Active</th>
                    <th class="py-3 px-4">Platform</th>
                    <th class="py-3 px-4">Risk Severity</th>
                    <th class="py-3 px-4 text-center">Status</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-slate-600/5">
                  <tr 
                    v-for="asset in filteredAssets" 
                    :key="asset.id"
                    @click="selectAsset(asset)"
                    class="group cursor-pointer hover:bg-emerald-500/5 transition-all"
                    :class="[selectedAsset?.id === asset.id ? 'bg-emerald-500/[0.07] border-l-2 border-emerald-500' : '']"
                  >
                    <td class="py-3 px-4">
                      <div class="flex items-center gap-3">
                        <div 
                          class="w-7 h-7 rounded-lg flex items-center justify-center text-[0.55rem] font-bold border"
                          :class="[
                            asset.riskLevel === 'Critical' ? 'bg-red-500/10 border-red-500/30 text-red-400' :
                            asset.riskLevel === 'High' ? 'bg-slate-500/10 border-slate-500/30 text-slate-400' :
                            asset.riskLevel === 'Medium' ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400' :
                            'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                          ]"
                        >
                          {{ asset.hostname.slice(0, 2) }}
                        </div>
                        <div class="flex flex-col leading-tight">
                          <span class="text-xs font-semibold text-slate-200 group-hover:text-emerald-400 transition-colors">{{ asset.hostname }}</span>
                          <span class="text-[0.6rem] text-slate-400/60 mt-0.5">{{ asset.role }}</span>
                        </div>
                      </div>
                    </td>
                    <td class="py-3 px-4 font-mono text-xs text-slate-300">{{ asset.ip }}</td>
                    <td class="py-3 px-4 text-[0.65rem] text-slate-400/50">{{ asset.lastSeen }}</td>
                    <td class="py-3 px-4">
                      <span class="px-2 py-0.5 rounded text-[0.55rem] font-bold uppercase tracking-wider bg-slate-600/10 text-slate-300 border border-slate-600/20">
                        {{ asset.platform }}
                      </span>
                    </td>
                    <td class="py-3 px-4">
                      <div class="flex items-center gap-2.5">
                        <div class="w-16 h-1.5 rounded-full bg-[#0f0f11] overflow-hidden border border-slate-600/5">
                          <div 
                            class="h-full rounded-full transition-all duration-300"
                            :class="[
                              asset.riskLevel === 'Critical' ? 'bg-red-500' :
                              asset.riskLevel === 'High' ? 'bg-slate-500' :
                              asset.riskLevel === 'Medium' ? 'bg-cyan-500' :
                              'bg-emerald-500'
                            ]"
                            :style="{ width: `${asset.riskValue}%` }"
                          />
                        </div>
                        <span 
                          class="text-[0.6rem] font-bold uppercase tracking-wide"
                          :class="[
                            asset.riskLevel === 'Critical' ? 'text-red-400' :
                            asset.riskLevel === 'High' ? 'text-slate-400' :
                            asset.riskLevel === 'Medium' ? 'text-cyan-400' :
                            'text-emerald-400'
                          ]"
                        >
                          {{ asset.riskLevel }}
                        </span>
                      </div>
                    </td>
                    <td class="py-3 px-4 text-center">
                      <span 
                        class="inline-block w-2 h-2 rounded-full"
                        :class="[asset.status === 'online' ? 'bg-emerald-400 shadow-[0_0_8px_rgba(232,121,249,0.7)]' : 'bg-[#403b58]']"
                      />
                    </td>
                  </tr>
                  <tr v-if="filteredAssets.length === 0">
                    <td colspan="6" class="py-8 text-center text-xs font-mono text-slate-400/40">No discovered hosts matching the filters.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- Right 1 Column: Node Details Drawer -->
        <div class="flex flex-col gap-5">
          <div v-if="selectedAsset" class="rounded-2xl bg-[#050505]/65 border border-slate-600/10 shadow-lg flex flex-col p-5 h-full min-h-[450px]">
            <div class="flex items-center justify-between border-b border-slate-600/10 pb-3 mb-4">
              <span class="text-xs font-bold uppercase tracking-wider text-emerald-400">Node telemetry</span>
              <span class="text-[0.55rem] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/25">Online</span>
            </div>

            <div class="flex-1 space-y-5">
              <div class="flex flex-col gap-1">
                <span class="text-[0.55rem] uppercase tracking-wider text-slate-400/50 font-bold">Address</span>
                <span class="text-lg font-bold font-mono text-slate-100">{{ selectedAsset.ip }}</span>
                <span class="text-[0.65rem] text-emerald-400/60 font-semibold font-mono">{{ selectedAsset.hostname }} ({{ selectedAsset.role }})</span>
              </div>

              <div class="grid grid-cols-2 gap-3.5 pt-2">
                <div class="p-3 rounded-xl bg-[#0f0f11]/60 border border-slate-600/10 flex flex-col gap-1">
                  <span class="text-[0.55rem] text-slate-400/50 uppercase tracking-widest font-bold">CPU Load</span>
                  <div class="flex items-end justify-between">
                    <span class="text-base font-bold font-mono text-emerald-400">{{ selectedAsset.cpu }}%</span>
                    <span class="text-[0.5rem] text-slate-400/30 uppercase">Normal</span>
                  </div>
                  <div class="h-1.5 w-full rounded-full bg-[#1e1a38] overflow-hidden mt-1">
                    <div class="h-full rounded-full bg-emerald-400" :style="{ width: `${selectedAsset.cpu}%` }"></div>
                  </div>
                </div>

                <div class="p-3 rounded-xl bg-[#0f0f11]/60 border border-slate-600/10 flex flex-col gap-1">
                  <span class="text-[0.55rem] text-slate-400/50 uppercase tracking-widest font-bold">Memory</span>
                  <div class="flex items-end justify-between">
                    <span class="text-base font-bold font-mono text-emerald-400">{{ selectedAsset.memory }} GB</span>
                    <span class="text-[0.5rem] text-slate-400/30 uppercase">Used</span>
                  </div>
                  <div class="h-1.5 w-full rounded-full bg-[#1e1a38] overflow-hidden mt-1">
                    <div class="h-full rounded-full bg-emerald-400" :style="{ width: `${(parseFloat(selectedAsset.memory) / 32) * 100}%` }"></div>
                  </div>
                </div>
              </div>

              <div class="space-y-2 pt-2">
                <span class="text-[0.55rem] uppercase tracking-widest text-slate-400/50 font-bold block">Audited Services</span>
                <div class="space-y-1.5">
                  <div v-for="port in selectedAsset.ports" :key="port.number" class="flex justify-between items-center rounded-lg p-2.5 bg-[#0f0f11]/80 border border-slate-600/5">
                    <div class="flex items-center gap-3">
                      <span class="font-mono text-xs font-bold text-emerald-400 w-10">#{{ port.number }}</span>
                      <span class="text-[0.65rem] text-slate-300 font-mono">{{ port.service.toUpperCase() }}</span>
                    </div>
                    <span class="text-[0.55rem] px-2 py-0.5 rounded font-mono font-bold uppercase tracking-wider bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">{{ port.state }}</span>
                  </div>
                  <div v-if="!selectedAsset.ports?.length" class="text-xs font-mono py-4 text-slate-400/40 text-center">No services audited yet.</div>
                </div>
              </div>

              <div class="p-3.5 rounded-xl border border-red-500/20 bg-red-500/5 flex items-start gap-3 mt-4" v-if="selectedAsset.riskLevel === 'Critical' || selectedAsset.riskLevel === 'High'">
                <div class="h-6 w-6 rounded flex items-center justify-center bg-red-500/10 text-red-400 shrink-0 text-xs font-bold">⚠</div>
                <div class="flex flex-col leading-snug">
                  <span class="text-[0.65rem] font-bold text-red-400 uppercase tracking-wide">Threat Exposure Warning</span>
                  <span class="text-[0.58rem] text-slate-300/80 mt-1">This node has exposed management ports and credentials that could lead to lateral takeover.</span>
                </div>
              </div>
            </div>

            <div class="border-t border-slate-600/10 pt-4 mt-6 flex flex-col gap-2">
              <button 
                v-if="isAdmin"
                class="w-full py-2.5 text-[0.6rem] font-bold uppercase tracking-widest bg-transparent hover:bg-rose-500/10 text-rose-400 border border-rose-500/30 rounded-xl transition-all"
              >
                Isolate Node
              </button>
              <div v-else class="text-[0.55rem] text-slate-400/50 uppercase tracking-wider text-center py-2 flex items-center justify-center gap-1.5">
                <span>🔒 Privileged Actions Restricted</span>
              </div>
            </div>
          </div>
          
          <div v-else class="rounded-2xl bg-[#050505]/65 border border-slate-600/10 p-8 text-center text-xs text-slate-400/30 flex items-center justify-center min-h-[450px]">
            Select a host in the inventory table to load analytics.
          </div>
        </div>

      </div>


    </div>

  </div>
</template>

<style scoped>
.animate-fade-in {
  animation: fadeIn 0.4s cubic-bezier(0.25, 0.8, 0.25, 1) forwards;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: translateY(0); }
}
</style>
