/**
 * Device discovery (discovery only).
 *
 * Wraps `POST /api/devices/discover`, which sweeps for hosts and records them
 * in the inventory without scanning any ports. Shared by the Devices inventory
 * and the Scanning console so both entry points behave identically.
 */
import axios from "axios";
import { ref } from "vue";

export interface DiscoveredHost {
  ip_address: string;
  mac_address: string | null;
  hostname: string | null;
  vendor: string | null;
  device_type: string | null;
  os: string | null;
  is_gateway: boolean;
  source: string;
}

export interface DiscoveryResult {
  created: number;
  updated: number;
  subnets: string[];
  methods: string[];
  skipped_restricted: string[];
  warnings: string[];
  hosts: DiscoveredHost[];
}

export type DiscoveryNotice = { kind: "ok" | "warn" | "error"; text: string };

/** Turn a completed sweep into a single sentence a human can act on. */
function summarise(result: DiscoveryResult): DiscoveryNotice {
  if (result.skipped_restricted.length > 0) {
    return {
      kind: "warn",
      text: `${result.skipped_restricted.join(", ")} is a restricted segment — skipped, passive monitoring only.`,
    };
  }
  if (result.warnings.length > 0) {
    return { kind: "warn", text: result.warnings.join(" ") };
  }

  const found = result.created + result.updated;
  if (found === 0) {
    const method = result.methods.length > 0 ? result.methods.join(" + ") : "no method";
    return { kind: "warn", text: `Sweep finished via ${method} but no hosts answered.` };
  }

  return {
    kind: "ok",
    text: `Found ${found} device${found === 1 ? "" : "s"} — ${result.created} new, ${result.updated} refreshed.`,
  };
}

export function useDeviceDiscovery() {
  const discovering = ref(false);
  const result = ref<DiscoveryResult | null>(null);
  const notice = ref<DiscoveryNotice | null>(null);

  async function discover(target?: string | null): Promise<DiscoveryResult | null> {
    if (discovering.value) return null;

    discovering.value = true;
    notice.value = null;
    try {
      const { data } = await axios.post<DiscoveryResult>("/api/devices/discover", {
        target: target?.trim() ? target.trim() : null,
      });
      result.value = data;
      notice.value = summarise(data);
      return data;
    } catch (e: any) {
      notice.value = {
        kind: "error",
        text: e?.response?.data?.detail || "Device discovery failed.",
      };
      return null;
    } finally {
      discovering.value = false;
    }
  }

  return { discovering, result, notice, discover };
}

/** Shared styling for a discovery notice, keyed on its kind. */
export function noticeStyle(kind: DiscoveryNotice["kind"]): Record<string, string> {
  const color =
    kind === "ok" ? "var(--np-success)" : kind === "warn" ? "var(--np-warning)" : "var(--np-danger)";
  return { borderColor: color, color };
}
