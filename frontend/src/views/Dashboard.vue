<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import axios from 'axios'
import PulsePanel from '../components/features/PulsePanel.vue'

import { resolveOui } from '../utils/oui'

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
  is_gateway?: boolean
}

interface AssetDetail extends Asset {
  mac_address?: string | null
  type_guess?: string | null
  zone?: string | null
  is_gateway?: boolean
  vulnerabilities: {
    id: number
    title: string
    severity: string
    port?: number | null
    detected_at?: string | null
  }[]
  scripts: {
    id: number
    script_name: string
    status: string
    created_at: string
  }[]
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
    assets.value = data.map((d: any) => {
      const typeLower = (d.device_type || '').toLowerCase();
      let platformVal: 'aws' | 'gcp' | 'azure' | 'linux' | 'windows' | 'cisco' = 'linux';
      if (typeLower.includes('windows')) {
        platformVal = 'windows';
      } else if (typeLower.includes('cisco') || typeLower.includes('switch')) {
        platformVal = 'cisco';
      } else if (typeLower.includes('aws')) {
        platformVal = 'aws';
      } else if (typeLower.includes('azure')) {
        platformVal = 'azure';
      } else if (typeLower.includes('gcp')) {
        platformVal = 'gcp';
      }
      
      return {
        id: d.id,
        ip: d.ip_address,
        hostname: d.hostname || d.ip_address,
        role: d.device_type || (d.is_gateway ? 'Gateway Router' : 'Network Host'),
        status: 'online',
        lastSeen: d.last_seen ? new Date(d.last_seen).toLocaleTimeString() : 'Unknown',
        platform: platformVal,
        riskLevel: d.is_gateway ? 'Medium' : 'Low',
        riskValue: d.is_gateway ? 50 : 20,
        is_gateway: d.is_gateway
      };
    })
    if (assets.value.length > 0) {
      await selectAsset(assets.value[0])
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

const selectAsset = async (asset: Asset) => {
  try {
    const { data } = await axios.get<any>(`/api/devices/${asset.id}/detail`)
    selectedAsset.value = {
      ...asset,
      mac_address: data.device.mac_address,
      type_guess: data.type_guess,
      zone: data.device.zone,
      is_gateway: data.device.is_gateway,
      vulnerabilities: data.vulnerabilities || [],
      scripts: data.scripts || []
    }
  } catch (error) {
    console.error("Failed to load device detail:", error)
    selectedAsset.value = {
      ...asset,
      mac_address: null,
      type_guess: null,
      zone: null,
      is_gateway: asset.is_gateway || false,
      vulnerabilities: [],
      scripts: []
    }
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
    <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-2xl bg-[var(--np-glass-bg)] border border-[var(--np-glass-border)] backdrop-blur-md">
      <div class="flex flex-col gap-1">
        <h2 class="text-base font-bold uppercase tracking-wider text-[var(--np-text)] font-sans">Network Operations &amp; Health</h2>
        <p class="text-[0.65rem] text-[var(--np-text-dim)]">Real-time status, latency diagnostic streams, and active inventory mapping.</p>
      </div>
    </div>

    <!-- Active view switch -->
    <div class="flex-1 min-h-0 relative z-10">
      
      <!-- ============================================ -->
      <!-- VIEW: IDENTITIES & HOSTS                     -->
      <!-- ============================================ -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-5 animate-fade-in">
        
        <!-- Left 2 Columns: Charts & Node Table -->
        <div class="lg:col-span-2 flex flex-col gap-5">
          
          <!-- Top row widget: Live Internet Health & Connection Quality Telemetry -->
          <PulsePanel />

          <!-- Bottom: Active Identities/Nodes Table Card -->
          <div class="rounded-2xl bg-[var(--np-glass-bg)] border border-[var(--np-glass-border)] shadow-lg flex flex-col flex-1 min-h-[350px]">
            <div class="p-4 border-b border-[var(--np-border-subtle)] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div class="flex items-center gap-3">
                <span class="text-xs font-bold uppercase tracking-wider text-[var(--np-text)]">{{ assets.length }} Discovered Network Hosts</span>
                <span class="text-[0.6rem] px-2 py-0.5 rounded-full font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Live</span>
              </div>
              
              <div class="flex items-center gap-2">
                <input 
                  type="text" 
                  v-model="searchQuery"
                  placeholder="Search hosts or IPs..."
                  class="np-neon-input text-xs px-3 py-1.5 w-44 font-mono"
                />
                <select 
                  v-model="selectedZoneFilter"
                  class="np-neon-input text-xs px-2 py-1.5 cursor-pointer"
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
                  <tr class="bg-[var(--np-thead-bg)] text-[0.6rem] text-[var(--np-text-dim)] uppercase tracking-widest border-b border-[var(--np-border-subtle)] font-bold">
                    <th class="py-3 px-4">Hostname &amp; Role</th>
                    <th class="py-3 px-4">IP Address</th>
                    <th class="py-3 px-4">Last Active</th>
                    <th class="py-3 px-4">Platform</th>
                    <th class="py-3 px-4">Risk Severity</th>
                    <th class="py-3 px-4 text-center">Status</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-[var(--np-border-subtle)]">
                  <tr 
                    v-for="asset in filteredAssets" 
                    :key="asset.id"
                    @click="selectAsset(asset)"
                    class="group cursor-pointer hover:bg-[var(--np-surface-hover)]/30 transition-all"
                    :class="[selectedAsset?.id === asset.id ? 'bg-[var(--np-accent-bg)] border-l-2 border-[var(--np-accent-primary)]' : '']"
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
                          <span class="text-xs font-semibold text-[var(--np-text)] group-hover:text-[var(--np-accent-primary)] transition-colors">{{ asset.hostname }}</span>
                          <span class="text-[0.6rem] text-[var(--np-text-muted)] mt-0.5">{{ asset.role }}</span>
                        </div>
                      </div>
                    </td>
                    <td class="py-3 px-4 font-mono text-xs text-[var(--np-text-muted)]">{{ asset.ip }}</td>
                    <td class="py-3 px-4 text-[0.65rem] text-[var(--np-text-dim)]">{{ asset.lastSeen }}</td>
                    <td class="py-3 px-4">
                      <span class="px-2 py-0.5 rounded text-[0.55rem] font-bold uppercase tracking-wider bg-[var(--np-surface-elevated)] text-[var(--np-text-muted)] border border-[var(--np-border-subtle)]">
                        {{ asset.platform }}
                      </span>
                    </td>
                    <td class="py-3 px-4">
                      <div class="flex items-center gap-2.5">
                        <div class="w-16 h-1.5 rounded-full bg-[var(--np-surface-elevated)] overflow-hidden border border-[var(--np-border-subtle)]">
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
                        :class="[asset.status === 'online' ? 'bg-emerald-400 shadow-[0_0_8px_rgba(34,197,94,0.7)]' : 'bg-slate-500']"
                      />
                    </td>
                  </tr>
                  <tr v-if="filteredAssets.length === 0">
                    <td colspan="6" class="py-8 text-center text-xs font-mono text-[var(--np-text-dim)]">No discovered hosts matching the filters.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- Right 1 Column: Node Details Drawer -->
        <div class="flex flex-col gap-5">
          <div v-if="selectedAsset" class="rounded-2xl bg-[var(--np-glass-bg)] border border-[var(--np-glass-border)] shadow-lg flex flex-col p-5 h-full min-h-[450px]">
            <div class="flex items-center justify-between border-b border-[var(--np-border-subtle)] pb-3 mb-4">
              <span class="text-xs font-bold uppercase tracking-wider text-[var(--np-accent-primary)]">Node details</span>
              <span class="text-[0.55rem] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/25">Online</span>
            </div>

            <div class="flex-1 space-y-5 overflow-y-auto custom-scrollbar pr-1">
              <div class="flex flex-col gap-1">
                <span class="text-[0.55rem] uppercase tracking-wider text-[var(--np-text-dim)] font-bold">Address</span>
                <span class="text-lg font-bold font-mono text-[var(--np-text)]">{{ selectedAsset.ip }}</span>
                <span class="text-[0.65rem] text-[var(--np-accent-primary)]/80 font-semibold font-mono">{{ selectedAsset.hostname }} ({{ selectedAsset.role }})</span>
                <router-link
                  :to="{ path: '/topology', query: { select: selectedAsset.id } }"
                  class="np-cyber-btn mt-2 text-center text-[10px] py-1 border-purple-500/40 text-purple-400 hover:bg-purple-500/10"
                >
                  Locate in Topology Map
                </router-link>
              </div>

              <!-- Real Details Table -->
              <dl class="space-y-2 text-xs border-t border-[var(--np-border-subtle)] pt-4">
                <div class="flex justify-between">
                  <dt class="text-[var(--np-text-dim)]">MAC Address</dt>
                  <dd class="font-mono text-[var(--np-text)]">{{ selectedAsset.mac_address || '—' }}</dd>
                </div>
                <div class="flex justify-between">
                  <dt class="text-[var(--np-text-dim)]">Vendor (OUI)</dt>
                  <dd class="text-[var(--np-text)]">
                    {{ selectedAsset.mac_address ? (resolveOui(selectedAsset.mac_address) ?? 'Unknown') : '—' }}
                  </dd>
                </div>
                <div class="flex justify-between">
                  <dt class="text-[var(--np-text-dim)]">Type</dt>
                  <dd class="text-[var(--np-text)]">{{ selectedAsset.type_guess || selectedAsset.role || '—' }}</dd>
                </div>
                <div class="flex justify-between">
                  <dt class="text-[var(--np-text-dim)]">Zone</dt>
                  <dd class="text-[var(--np-text)]">{{ selectedAsset.zone || '—' }}</dd>
                </div>
                <div class="flex justify-between">
                  <dt class="text-[var(--np-text-dim)]">Gateway</dt>
                  <dd :class="[selectedAsset.is_gateway ? 'text-emerald-400 font-bold' : 'text-[var(--np-text-dim)]']">
                    {{ selectedAsset.is_gateway ? 'Yes' : 'No' }}
                  </dd>
                </div>
                <div class="flex justify-between">
                  <dt class="text-[var(--np-text-dim)]">Last Seen</dt>
                  <dd class="text-[var(--np-text)]">{{ selectedAsset.lastSeen }}</dd>
                </div>
              </dl>

              <!-- Real Vulnerabilities section -->
              <div class="space-y-2 pt-2 border-t border-[var(--np-border-subtle)]">
                <span class="text-[0.55rem] uppercase tracking-widest text-[var(--np-text-dim)] font-bold block">
                  Vulnerabilities ({{ selectedAsset.vulnerabilities?.length || 0 }})
                </span>
                <div class="space-y-1.5">
                  <div v-for="vuln in selectedAsset.vulnerabilities" :key="vuln.id" class="flex justify-between items-center rounded-lg p-2.5 bg-[var(--np-surface-elevated)] border border-[var(--np-border-subtle)]">
                    <div class="flex items-center gap-2">
                      <span :class="[
                        vuln.severity === 'critical' ? 'text-red-500 font-bold' :
                        vuln.severity === 'high' ? 'text-orange-500 font-bold' :
                        vuln.severity === 'medium' ? 'text-yellow-500 font-bold' :
                        'text-emerald-400'
                      ]" class="font-mono text-[0.65rem] shrink-0">
                        [{{ vuln.severity.toUpperCase() }}]
                      </span>
                      <span class="text-[0.65rem] text-[var(--np-text)] truncate max-w-[180px]">{{ vuln.title }}</span>
                    </div>
                    <span v-if="vuln.port" class="text-[0.65rem] font-mono text-[var(--np-text-dim)]">:{{ vuln.port }}</span>
                  </div>
                  <div v-if="!selectedAsset.vulnerabilities?.length" class="text-xs font-mono py-2 text-[var(--np-text-dim)] text-center">No vulnerabilities detected.</div>
                </div>
              </div>

              <!-- Real Scripts execution section -->
              <div class="space-y-2 pt-2 border-t border-[var(--np-border-subtle)]">
                <span class="text-[0.55rem] uppercase tracking-widest text-[var(--np-text-dim)] font-bold block">
                  Recent Script Jobs
                </span>
                <div class="space-y-1.5">
                  <div v-for="s in selectedAsset.scripts" :key="s.id" class="flex justify-between items-center rounded-lg p-2 bg-[var(--np-surface-elevated)] border border-[var(--np-border-subtle)] text-[0.65rem]">
                    <span class="font-mono text-[var(--np-text)] truncate max-w-[180px]">{{ s.script_name }}</span>
                    <span :class="[
                      s.status === 'success' ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' :
                      s.status === 'failed' ? 'text-red-400 bg-red-500/10 border-red-500/20' :
                      'text-yellow-400 bg-yellow-500/10 border-yellow-500/20'
                    ]" class="px-1.5 py-0.5 rounded font-mono border text-[0.55rem] uppercase">
                      {{ s.status }}
                    </span>
                  </div>
                  <div v-if="!selectedAsset.scripts?.length" class="text-xs font-mono py-2 text-[var(--np-text-dim)] text-center">No scripts executed.</div>
                </div>
              </div>
            </div>

            <div class="border-t border-[var(--np-border-subtle)] pt-4 mt-4 flex flex-col gap-2">
              <button 
                v-if="isAdmin"
                class="w-full py-2.5 text-[0.6rem] font-bold uppercase tracking-widest bg-transparent hover:bg-rose-500/10 text-rose-400 border border-rose-500/30 rounded-xl transition-all"
              >
                Isolate Node
              </button>
              <div v-else class="text-[0.55rem] text-[var(--np-text-dim)] uppercase tracking-wider text-center py-2 flex items-center justify-center gap-1.5">
                <span>🔒 Privileged Actions Restricted</span>
              </div>
            </div>
          </div>
          
          <div v-else class="rounded-2xl bg-[var(--np-glass-bg)] border border-[var(--np-glass-border)] p-8 text-center text-xs text-[var(--np-text-dim)] flex items-center justify-center min-h-[450px]">
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
