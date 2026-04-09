import { defineStore } from "pinia";
import { ref } from "vue";
import axios from "axios";
import { resolveOui } from "../utils/oui";

export interface Device {
  id: number;
  hostname: string | null;
  ip_address: string;
  mac_address: string | null;
  device_type: string | null;
  is_gateway: boolean;
  zone: string | null;
  last_seen: string | null;
  vendor?: string | null;
}

export const useDevicesStore = defineStore("devices", () => {
  const devices = ref<Device[]>([]);
  const loading = ref(false);
  const error = ref<string | null>(null);

  async function fetchDevices(zone?: string | null) {
    loading.value = true;
    error.value = null;
    try {
      const params: Record<string, string> = {};
      if (zone) params.zone = zone;
      const { data } = await axios.get<Device[]>("/api/devices", { params });
      // Resolve vendor names passively from the MAC OUI.
      devices.value = data.map((d) => ({
        ...d,
        vendor: d.mac_address ? resolveOui(d.mac_address) : null,
      }));
    } catch (e: any) {
      error.value = e?.response?.data?.error?.message ?? "Failed to load devices";
    } finally {
      loading.value = false;
    }
  }

  return { devices, loading, error, fetchDevices };
});
