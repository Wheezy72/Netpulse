/**
 * Passive MAC OUI fingerprinting utility.
 *
 * Maintains a lightweight in-memory table of the most common OUI prefixes.
 * For full coverage, the backend can expose a /api/oui/{mac} lookup that
 * queries a complete IEEE database.
 *
 * Usage:  resolveOui("00:1A:2B:3C:4D:5E")  → "Cisco Systems"
 */

// Trimmed common-vendor OUI table (first 3 octets, uppercase, no separators).
// Extend this as needed or wire up the backend OUI endpoint.
const OUI_TABLE: Record<string, string> = {
  "001A2B": "Cisco Systems",
  "0050C2": "Cisco Systems",
  "5C5015": "Cisco Systems",
  "00059A": "Cisco-Linksys",
  "001315": "Cisco-Linksys",
  "000C29": "VMware",
  "001C14": "VMware",
  "005056": "VMware",
  "0003FF": "Microsoft",
  "28184D": "Microsoft",
  "DC4A9E": "Microsoft",
  "0026BB": "Apple",
  "3C0754": "Apple",
  "A45E60": "Apple",
  "B8E856": "Apple",
  "F0DCE2": "Apple",
  "001E06": "Juniper Networks",
  "0019E2": "Juniper Networks",
  "2C6BF5": "HP Enterprise",
  "3C4A92": "HP Enterprise",
  "001708": "HP Inc",
  "E0D55E": "Dell",
  "F0761C": "Dell",
  "0021B7": "Dell",
  "BC9FEF": "Ubiquiti",
  "DC9FDB": "Ubiquiti",
  "E063DA": "Ubiquiti",
  "246895": "Fortinet",
  "0009BF": "Fortinet",
  "70B3D5": "IEEE Registration Authority",
  "000000": "Xerox",
  "ACDE48": "Private",
};

/** Return the vendor name for a given MAC address, or null if unknown. */
export function resolveOui(mac: string): string | null {
  if (!mac) return null;
  // Normalise: remove separators, uppercase, take first 6 hex chars (3 octets).
  const oui = mac.replace(/[:\-\.]/g, "").toUpperCase().slice(0, 6);
  return OUI_TABLE[oui] ?? null;
}
