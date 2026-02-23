from __future__ import annotations

import logging
import re
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.api.routes.settings import _ai_settings, AISettings
from app.models.user import User

logger = logging.getLogger(__name__)

router = APIRouter()

ALLOWED_FILE_TYPES = {
    "pcap": ["application/vnd.tcpdump.pcap", "application/octet-stream"],
    "log": ["text/plain", "text/x-log", "application/octet-stream"],
    "txt": ["text/plain"],
    "json": ["application/json"],
    "csv": ["text/csv"],
}

MAX_FILE_SIZE = 10 * 1024 * 1024


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str
    context: Optional[str] = None


class ChatResponse(BaseModel):
    response: str
    suggestions: List[str]


NETWORK_KNOWLEDGE: dict[str, dict[str, str]] = {
    "nmap": {
        "quick scan": "Use `nmap -T4 -F target` for a fast scan of the 100 most common ports.",
        "full port": "Use `nmap -p- target` to scan all 65535 ports. Add `-T4` for speed.",
        "service detection": "Use `nmap -sV target` to detect service versions on open ports.",
        "os detection": "Use `nmap -O target` to detect the operating system. Requires root.",
        "vulnerability": "Use `nmap --script=vuln target` to run vulnerability detection scripts.",
        "stealth": "Use `nmap -sS target` for a SYN stealth scan. Requires root privileges.",
    },
    "troubleshooting": {
        "slow network": (
            "To diagnose slow network performance:\n"
            "1. Check bandwidth usage with `iftop` or `nethogs`\n"
            "2. Run `ping` to test latency to key hosts\n"
            "3. Check for packet loss with `mtr target`\n"
            "4. Verify DNS resolution with `dig` or `nslookup`\n"
            "5. Check switch/router interface errors and CRC counts"
        ),
        "connectivity": (
            "To troubleshoot connectivity:\n"
            "1. Verify physical link status\n"
            "2. Check IP configuration with `ip addr`\n"
            "3. Test gateway reachability with `ping`\n"
            "4. Verify routing table with `ip route`\n"
            "5. Check firewall rules with `iptables -L`"
        ),
        "dns issues": (
            "To troubleshoot DNS:\n"
            "1. Test DNS resolution: `nslookup domain.com`\n"
            "2. Check /etc/resolv.conf for correct nameservers\n"
            "3. Try alternative DNS: `dig @8.8.8.8 domain.com`\n"
            "4. Clear DNS cache if applicable\n"
            "5. Check for DNS firewall blocks on port 53"
        ),
    },
    "security": {
        "hardening": (
            "Key steps for network hardening:\n"
            "1. Disable unnecessary services\n"
            "2. Keep systems patched and updated\n"
            "3. Implement network segmentation\n"
            "4. Use strong authentication (MFA where possible)\n"
            "5. Enable logging and monitoring\n"
            "6. Configure firewalls with least-privilege rules"
        ),
        "ports": (
            "Common ports to monitor:\n"
            "- 22 (SSH) - Secure shell access\n"
            "- 23 (Telnet) - Should be disabled\n"
            "- 80/443 (HTTP/HTTPS) - Web traffic\n"
            "- 3389 (RDP) - Remote desktop\n"
            "- 445 (SMB) - File sharing"
        ),
    },
}

GENERAL_KNOWLEDGE: dict[str, tuple[str, list[str]]] = {
    "subnetting": (
        "**Subnetting Quick Reference:**\n\n"
        "| CIDR | Subnet Mask     | Hosts  |\n"
        "|------|----------------|--------|\n"
        "| /24  | 255.255.255.0  | 254    |\n"
        "| /25  | 255.255.255.128| 126    |\n"
        "| /26  | 255.255.255.192| 62     |\n"
        "| /27  | 255.255.255.224| 30     |\n"
        "| /28  | 255.255.255.240| 14     |\n"
        "| /30  | 255.255.255.252| 2      |\n\n"
        "Formula: Hosts = 2^(32 - prefix) - 2\n\n"
        "Example: 192.168.1.0/24 gives you 192.168.1.1 to 192.168.1.254 for hosts.",
        ["How do I calculate subnets?", "What CIDR should I use for 50 hosts?", "Explain VLSM"]
    ),
    "vlan": (
        "**VLANs (Virtual LANs):**\n\n"
        "VLANs segment a physical network into logical groups.\n\n"
        "**Benefits:**\n"
        "- Isolate broadcast domains\n"
        "- Improve security (separate sensitive traffic)\n"
        "- Better performance (less broadcast noise)\n\n"
        "**Common setup:**\n"
        "- VLAN 1: Default/Management\n"
        "- VLAN 10: Servers\n"
        "- VLAN 20: Workstations\n"
        "- VLAN 30: Guest/IoT\n"
        "- VLAN 99: Trunk native\n\n"
        "Use 802.1Q trunking between switches to carry VLAN traffic.",
        ["How to configure VLANs?", "What is VLAN trunking?", "Best VLAN design practices"]
    ),
    "firewall": (
        "**Firewall Best Practices:**\n\n"
        "1. **Default deny** - Block all traffic by default, whitelist what's needed\n"
        "2. **Least privilege** - Only open ports that are required\n"
        "3. **Zone-based** - Segment into zones (WAN, LAN, DMZ, Guest)\n"
        "4. **Logging** - Log denied traffic for analysis\n"
        "5. **Regular audit** - Review rules quarterly\n\n"
        "**Popular firewalls:**\n"
        "- pfSense / OPNsense (open source)\n"
        "- Fortinet FortiGate\n"
        "- Palo Alto Networks\n"
        "- Cisco ASA / Firepower",
        ["How to set up pfSense?", "What ports should I block?", "DMZ configuration tips"]
    ),
    "vpn": (
        "**VPN Options for Home Lab / Enterprise:**\n\n"
        "**WireGuard** - Modern, fast, simple config\n"
        "- Best for: Site-to-site, remote access\n"
        "- Config: ~10 lines per peer\n\n"
        "**OpenVPN** - Proven, flexible\n"
        "- Best for: Complex setups, certificate-based auth\n\n"
        "**IPSec/IKEv2** - Enterprise standard\n"
        "- Best for: Corporate VPNs, mobile devices\n\n"
        "**Tailscale/ZeroTier** - Zero-config mesh VPN\n"
        "- Best for: Quick setup, distributed teams",
        ["How to set up WireGuard?", "VPN vs Zero Trust", "Site-to-site VPN guide"]
    ),
    "docker": (
        "**Docker Networking Basics:**\n\n"
        "**Network types:**\n"
        "- `bridge` - Default, containers on same host\n"
        "- `host` - Container uses host's network stack\n"
        "- `macvlan` - Container gets its own MAC/IP on LAN\n"
        "- `overlay` - Multi-host (Docker Swarm)\n\n"
        "**Common commands:**\n"
        "```\n"
        "docker network ls\n"
        "docker network create mynet\n"
        "docker run --network mynet ...\n"
        "docker network inspect bridge\n"
        "```\n\n"
        "**Port mapping:** `-p 8080:80` maps host 8080 to container 80",
        ["Docker compose networking", "Macvlan setup guide", "Container DNS resolution"]
    ),
    "proxmox": (
        "**Proxmox VE Networking:**\n\n"
        "Proxmox uses Linux bridges for VM networking.\n\n"
        "**Setup tips:**\n"
        "1. `vmbr0` - Main bridge, linked to physical NIC\n"
        "2. Add VLAN awareness: `bridge-vlan-aware yes`\n"
        "3. For VMs: assign bridge + VLAN tag\n"
        "4. For containers: use `veth` pairs\n\n"
        "**Network config:** `/etc/network/interfaces`\n\n"
        "**Firewall:** Proxmox has built-in firewall at datacenter, node, and VM level.",
        ["Proxmox VLAN setup", "Proxmox cluster networking", "VM vs container networking"]
    ),
    "monitoring": (
        "**Network Monitoring Tools:**\n\n"
        "**Open Source:**\n"
        "- **Zabbix** - Enterprise monitoring, SNMP, agents\n"
        "- **Grafana + Prometheus** - Metrics and dashboards\n"
        "- **LibreNMS** - Auto-discovery, SNMP-based\n"
        "- **Nagios/Icinga** - Classic host/service checks\n"
        "- **Uptime Kuma** - Simple uptime monitoring\n\n"
        "**What to monitor:**\n"
        "- Bandwidth utilization\n"
        "- Latency and packet loss\n"
        "- CPU/memory on network devices\n"
        "- Interface errors and discards\n"
        "- Syslog and SNMP traps",
        ["How to set up SNMP?", "Best Grafana dashboards?", "Alerting best practices"]
    ),
    "homelab": (
        "**Home Lab Networking Tips:**\n\n"
        "**Recommended Architecture:**\n"
        "1. **Router/Firewall**: pfSense or OPNsense on mini PC\n"
        "2. **Switch**: Managed switch with VLAN support\n"
        "3. **Wi-Fi**: Ubiquiti APs or TP-Link Omada\n"
        "4. **Server**: Proxmox for VMs and containers\n\n"
        "**Network segmentation:**\n"
        "- Management VLAN (switches, APs, IPMI)\n"
        "- Server VLAN (services, storage)\n"
        "- User VLAN (desktops, laptops)\n"
        "- IoT VLAN (cameras, smart devices)\n"
        "- Guest VLAN (isolated internet only)",
        ["Best homelab hardware?", "How to segment IoT?", "Proxmox vs ESXi?"]
    ),
    "python": (
        "**Python for Network Automation:**\n\n"
        "**Key libraries:**\n"
        "- `scapy` - Packet crafting and sniffing\n"
        "- `paramiko` / `netmiko` - SSH to network devices\n"
        "- `nmap` (python-nmap) - Programmatic scanning\n"
        "- `requests` - REST API calls\n"
        "- `pysnmp` - SNMP queries\n"
        "- `socket` - Low-level network programming\n\n"
        "**Example - ping sweep:**\n"
        "```python\n"
        "import subprocess\n"
        "for i in range(1, 255):\n"
        "    ip = f'192.168.1.{i}'\n"
        "    result = subprocess.run(\n"
        "        ['ping', '-c', '1', '-W', '1', ip],\n"
        "        capture_output=True\n"
        "    )\n"
        "    if result.returncode == 0:\n"
        "        print(f'{ip} is alive')\n"
        "```",
        ["How to use netmiko?", "Scapy packet crafting", "Automate switch config"]
    ),
    "wireshark": (
        "**Wireshark / tshark Tips:**\n\n"
        "**Common display filters:**\n"
        "- `ip.addr == 192.168.1.1` - Traffic to/from IP\n"
        "- `tcp.port == 443` - HTTPS traffic\n"
        "- `http.request` - HTTP requests only\n"
        "- `dns` - DNS queries and responses\n"
        "- `tcp.flags.syn == 1` - SYN packets (new connections)\n"
        "- `tcp.analysis.retransmission` - Retransmissions\n\n"
        "**tshark one-liners:**\n"
        "```\n"
        "tshark -i eth0 -c 100  # Capture 100 packets\n"
        "tshark -r file.pcap -qz io,phs  # Protocol hierarchy\n"
        "tshark -r file.pcap -qz conv,ip  # Top talkers\n"
        "```",
        ["How to find slow connections?", "Capture specific traffic", "Analyze packet loss"]
    ),
}

TOPIC_KEYWORDS: list[tuple[list[str], str]] = [
    (["nse", "nse script", "script=", "--script"], "nse_scripts"),
    (["nmap", "scan", "port scan"], "nmap"),
    (["scan result", "scan output", "interpret scan", "open port", "filtered port", "closed port", "nmap output", "nmap result"], "scan_results"),
    (["block", "quarantine", "isolate", "blacklist", "deny", "ban device", "block device", "block ip"], "blocking"),
    (["snmp", "oid", "community string", "mib", "snmpwalk", "snmpget", "polling"], "snmp"),
    (["syslog", "severity", "log level", "facility", "log pattern", "rsyslog"], "syslog"),
    (["slow", "latency", "bottleneck", "bandwidth", "speed"], "slow_network"),
    (["connect", "unreachable", "down", "offline", "timeout"], "connectivity"),
    (["dns", "resolve", "nslookup", "nameserver"], "dns"),
    (["traceroute", "tracert", "mtr", "hop", "path"], "traceroute"),
    (["ping", "icmp", "echo request", "packet loss"], "ping"),
    (["security", "harden", "secure", "vulnerability", "attack"], "security"),
    (["subnet", "cidr", "netmask", "/24", "/16"], "subnetting"),
    (["vlan", "802.1q", "trunk"], "vlan"),
    (["firewall", "iptables", "pfsense", "opnsense", "acl"], "firewall"),
    (["vpn", "wireguard", "openvpn", "ipsec", "tailscale", "zerotier"], "vpn"),
    (["docker", "container", "kubernetes", "k8s", "compose"], "docker"),
    (["proxmox", "esxi", "vmware", "virtualization", "hypervisor", "vm"], "proxmox"),
    (["monitor", "grafana", "prometheus", "zabbix", "nagios", "librenms"], "monitoring"),
    (["homelab", "home lab", "home network", "home server"], "homelab"),
    (["python", "script", "automate", "automation", "netmiko", "paramiko", "scapy"], "python"),
    (["wireshark", "pcap", "tshark", "packet capture", "packet analysis"], "wireshark"),
    (["port", "common port", "well-known"], "ports"),
    (["router", "routing", "ospf", "bgp", "rip", "static route"], "router"),
    (["switch", "switching", "stp", "spanning tree", "mac address"], "switch"),
    (["wifi", "wireless", "ssid", "wpa", "802.11", "access point", "ap"], "wifi"),
    (["ip", "ipv4", "ipv6", "dhcp", "address"], "ip_addressing"),
    (["ssl", "tls", "certificate", "https", "encryption", "cert"], "tls"),
    (["backup", "disaster recovery", "restore", "snapshot"], "backup"),
    (["bandwidth", "throughput", "iperf", "speed test"], "bandwidth"),
    (["log", "logging", "journalctl"], "logging"),
]


def _match_topic(message: str) -> Optional[str]:
    msg_lower = message.lower()
    for keywords, topic in TOPIC_KEYWORDS:
        if any(kw in msg_lower for kw in keywords):
            return topic
    return None


def _get_nmap_response(message: str) -> tuple[str, list[str]]:
    msg_lower = message.lower()
    if "quick" in msg_lower or "fast" in msg_lower:
        return NETWORK_KNOWLEDGE["nmap"]["quick scan"], ["How do I detect service versions?", "What's a stealth scan?"]
    elif "full" in msg_lower or "all port" in msg_lower:
        return NETWORK_KNOWLEDGE["nmap"]["full port"], ["How long does a full scan take?", "How to speed up scanning?"]
    elif "vuln" in msg_lower or "vulnerability" in msg_lower:
        return NETWORK_KNOWLEDGE["nmap"]["vulnerability"], ["What vulnerabilities does this detect?", "How to interpret results?"]
    elif "version" in msg_lower or "service" in msg_lower:
        return NETWORK_KNOWLEDGE["nmap"]["service detection"], ["What does -sV show?", "How accurate is version detection?"]
    elif "os" in msg_lower or "operating system" in msg_lower:
        return NETWORK_KNOWLEDGE["nmap"]["os detection"], ["Why does OS detection need root?", "How accurate is OS detection?"]
    elif "stealth" in msg_lower or "syn" in msg_lower:
        return NETWORK_KNOWLEDGE["nmap"]["stealth"], ["When should I use stealth scans?", "Is stealth scanning detectable?"]
    else:
        return (
            "Here are common nmap scan types:\n\n"
            "- **Quick scan**: `nmap -T4 -F target`\n"
            "- **Full port scan**: `nmap -p- target`\n"
            "- **Service detection**: `nmap -sV target`\n"
            "- **OS detection**: `nmap -O target`\n"
            "- **Vulnerability scan**: `nmap --script=vuln target`\n"
            "- **Stealth scan**: `nmap -sS target`\n\n"
            "What specific type of scan do you need?",
            ["How to scan for vulnerabilities?", "What's the fastest scan?", "How to detect OS?"]
        )


EXTENDED_TOPICS: dict[str, tuple[str, list[str]]] = {
    "nse_scripts": (
        "**NSE (Nmap Scripting Engine) Guide:**\n\n"
        "NSE scripts extend nmap with powerful detection and enumeration capabilities.\n\n"
        "**Common NSE script categories:**\n"
        "| Category | Usage | Example |\n"
        "|----------|-------|---------|\n"
        "| `vuln` | Vulnerability detection | `nmap --script=vuln target` |\n"
        "| `auth` | Authentication checks | `nmap --script=auth target` |\n"
        "| `brute` | Brute-force attacks | `nmap --script=brute target` |\n"
        "| `discovery` | Service discovery | `nmap --script=discovery target` |\n"
        "| `safe` | Non-intrusive scripts | `nmap --script=safe target` |\n\n"
        "**Popular individual scripts:**\n"
        "- `http-title` - Grab web page titles\n"
        "- `ssl-enum-ciphers` - List supported TLS ciphers\n"
        "- `smb-os-discovery` - Detect Windows OS via SMB\n"
        "- `dns-brute` - Brute-force DNS subdomains\n"
        "- `vuln` (category) - Run all vulnerability checks\n"
        "- `http-enum` - Enumerate web directories\n"
        "- `ssh-auth-methods` - Check SSH authentication types\n"
        "- `ftp-anon` - Check for anonymous FTP access\n"
        "- `mysql-info` - Grab MySQL server info\n"
        "- `snmp-info` - Enumerate SNMP information\n\n"
        "**Running scripts:**\n"
        "```\n"
        "nmap --script=http-title target          # Single script\n"
        "nmap --script=vuln,safe target           # Multiple categories\n"
        "nmap --script=\"http-*\" target            # Wildcard match\n"
        "nmap --script-args user=admin target     # With arguments\n"
        "ls /usr/share/nmap/scripts/              # List all scripts\n"
        "```",
        ["Which NSE script detects vulnerabilities?", "How to write custom NSE scripts?", "Best NSE scripts for web apps"]
    ),
    "scan_results": (
        "**Interpreting Nmap Scan Results:**\n\n"
        "**Port states explained:**\n"
        "- **open** - A service is actively listening and accepting connections\n"
        "- **closed** - Port is accessible but no service is listening\n"
        "- **filtered** - Nmap cannot determine if port is open (firewall blocking probes)\n"
        "- **unfiltered** - Port is accessible but nmap can't tell if open/closed\n"
        "- **open|filtered** - Cannot determine which of the two states\n"
        "- **closed|filtered** - Cannot determine which of the two states\n\n"
        "**Reading the output:**\n"
        "```\n"
        "PORT     STATE  SERVICE    VERSION\n"
        "22/tcp   open   ssh        OpenSSH 8.9p1\n"
        "80/tcp   open   http       Apache httpd 2.4.52\n"
        "443/tcp  open   https      nginx 1.18.0\n"
        "3306/tcp closed mysql\n"
        "8080/tcp filtered http-proxy\n"
        "```\n\n"
        "**Key things to look for:**\n"
        "- Unexpected open ports (possible backdoor or misconfiguration)\n"
        "- Outdated service versions (security risk)\n"
        "- Services running on non-standard ports\n"
        "- Filtered ports may indicate firewall protection\n"
        "- OS detection results for fingerprinting\n\n"
        "**Response actions:**\n"
        "1. Close unnecessary open ports\n"
        "2. Update outdated services\n"
        "3. Investigate unknown services\n"
        "4. Verify filtered ports are intentionally blocked",
        ["What does filtered mean?", "How to close an open port?", "How to identify suspicious services?"]
    ),
    "blocking": (
        "**Blocking & Quarantining Devices:**\n\n"
        "**Methods to block/quarantine a device on your network:**\n\n"
        "**1. Firewall rules (iptables/nftables):**\n"
        "```\n"
        "# Block a specific IP\n"
        "iptables -A INPUT -s 192.168.1.100 -j DROP\n"
        "iptables -A FORWARD -s 192.168.1.100 -j DROP\n\n"
        "# Block a MAC address\n"
        "iptables -A INPUT -m mac --mac-source AA:BB:CC:DD:EE:FF -j DROP\n"
        "```\n\n"
        "**2. Switch port security:**\n"
        "- Shut down the switch port: `interface shutdown`\n"
        "- Move to quarantine VLAN\n"
        "- Apply port security to limit MAC addresses\n\n"
        "**3. DHCP reservation/deny:**\n"
        "- Deny DHCP lease to the device's MAC\n"
        "- Assign a quarantine IP range\n\n"
        "**4. Router ACLs:**\n"
        "```\n"
        "# Cisco-style ACL\n"
        "access-list 100 deny ip host 192.168.1.100 any\n"
        "access-list 100 permit ip any any\n"
        "```\n\n"
        "**5. Network quarantine VLAN:**\n"
        "- Create an isolated VLAN with no internet/LAN access\n"
        "- Move the device's port to this VLAN\n"
        "- Useful for investigation without full disconnection\n\n"
        "**NetPulse integration:** Use the Device Actions panel to block or quarantine devices directly from the dashboard.",
        ["How to unblock a device?", "Set up a quarantine VLAN", "Automate blocking with scripts"]
    ),
    "snmp": (
        "**SNMP (Simple Network Management Protocol):**\n\n"
        "**Versions:**\n"
        "- **SNMPv1** - Basic, community string auth (insecure)\n"
        "- **SNMPv2c** - Improved, still community strings\n"
        "- **SNMPv3** - Encrypted, user-based authentication (recommended)\n\n"
        "**Key concepts:**\n"
        "- **OID** (Object Identifier) - Unique address for each metric\n"
        "- **MIB** (Management Information Base) - Database of OIDs\n"
        "- **Community String** - Password for SNMPv1/v2c (default: `public`)\n"
        "- **Polling** - Querying devices at intervals for metrics\n"
        "- **Traps** - Devices send alerts to the manager\n\n"
        "**Common OIDs:**\n"
        "| OID | Description |\n"
        "|-----|-------------|\n"
        "| `.1.3.6.1.2.1.1.1.0` | System description |\n"
        "| `.1.3.6.1.2.1.1.3.0` | System uptime |\n"
        "| `.1.3.6.1.2.1.1.5.0` | System hostname |\n"
        "| `.1.3.6.1.2.1.2.2.1.10` | Interface bytes in |\n"
        "| `.1.3.6.1.2.1.2.2.1.16` | Interface bytes out |\n"
        "| `.1.3.6.1.2.1.25.3.3.1.2` | CPU usage |\n"
        "| `.1.3.6.1.2.1.25.2.3.1.6` | Memory used |\n\n"
        "**Useful commands:**\n"
        "```\n"
        "# Walk all OIDs\n"
        "snmpwalk -v2c -c public 192.168.1.1\n\n"
        "# Get specific OID\n"
        "snmpget -v2c -c public 192.168.1.1 .1.3.6.1.2.1.1.1.0\n\n"
        "# SNMPv3 query\n"
        "snmpget -v3 -u myuser -l authPriv -a SHA -A mypass \\\n"
        "  -x AES -X mypriv 192.168.1.1 sysDescr.0\n"
        "```\n\n"
        "**Security tips:**\n"
        "- Never use default community strings (`public`/`private`)\n"
        "- Prefer SNMPv3 with authentication and encryption\n"
        "- Restrict SNMP access with ACLs\n"
        "- Use separate read-only and read-write community strings",
        ["How to configure SNMPv3?", "What OIDs should I monitor?", "SNMP polling best practices"]
    ),
    "syslog": (
        "**Syslog Reference Guide:**\n\n"
        "**Severity levels (RFC 5424):**\n"
        "| Level | Name | Description |\n"
        "|-------|------|-------------|\n"
        "| 0 | Emergency | System is unusable |\n"
        "| 1 | Alert | Immediate action needed |\n"
        "| 2 | Critical | Critical conditions |\n"
        "| 3 | Error | Error conditions |\n"
        "| 4 | Warning | Warning conditions |\n"
        "| 5 | Notice | Normal but significant |\n"
        "| 6 | Informational | Informational messages |\n"
        "| 7 | Debug | Debug-level messages |\n\n"
        "**Facility codes:**\n"
        "- `0` kern - Kernel messages\n"
        "- `1` user - User-level messages\n"
        "- `4` auth - Security/auth messages\n"
        "- `10` authpriv - Private auth messages\n"
        "- `16-23` local0-local7 - Custom use\n\n"
        "**Common log patterns to watch:**\n"
        "- `Failed password` - Brute-force attempts\n"
        "- `link down` / `link up` - Interface flapping\n"
        "- `temperature` - Hardware warnings\n"
        "- `denied` / `dropped` - Firewall blocks\n"
        "- `config changed` - Unauthorized changes\n"
        "- `authentication failure` - Login failures\n\n"
        "**Setting up syslog forwarding:**\n"
        "```\n"
        "# On network device (Cisco example)\n"
        "logging host 192.168.1.10\n"
        "logging trap informational\n"
        "logging facility local7\n\n"
        "# On syslog server (rsyslog)\n"
        "module(load=\"imudp\")\n"
        "input(type=\"imudp\" port=\"514\")\n"
        "local7.* /var/log/network.log\n"
        "```\n\n"
        "**NetPulse integration:** Configure syslog receivers in Settings to collect logs from your network devices automatically.",
        ["How to filter syslog messages?", "Set up syslog alerting", "Best log retention policy"]
    ),
    "traceroute": (
        "**Traceroute / MTR Guide:**\n\n"
        "**Basic usage:**\n"
        "```\n"
        "traceroute target           # UDP probes (Linux)\n"
        "tracert target              # ICMP probes (Windows)\n"
        "mtr target                  # Interactive + statistics\n"
        "mtr -rwc 100 target         # Report mode, 100 packets\n"
        "```\n\n"
        "**Reading the output:**\n"
        "- Each line = one hop (router) along the path\n"
        "- `* * *` = hop not responding (firewall or ICMP disabled)\n"
        "- High latency at one hop = potential bottleneck\n"
        "- Packet loss at one hop but not later = ICMP rate limiting (normal)\n"
        "- Packet loss from one hop onward = real congestion/issue\n\n"
        "**Common issues:**\n"
        "- Asymmetric routing (different paths each direction)\n"
        "- ISP congestion at peering points\n"
        "- Last-mile issues (first/last hop problems)",
        ["How to read traceroute?", "What does * * * mean?", "mtr vs traceroute"]
    ),
    "ping": (
        "**Ping & ICMP Troubleshooting:**\n\n"
        "**Basic commands:**\n"
        "```\n"
        "ping target                 # Basic connectivity test\n"
        "ping -c 100 target          # Send 100 packets (statistics)\n"
        "ping -s 1472 -M do target   # MTU test (don't fragment)\n"
        "ping -f target              # Flood ping (requires root)\n"
        "ping -I eth0 target         # Use specific interface\n"
        "```\n\n"
        "**Interpreting results:**\n"
        "- **0% loss** - Healthy connection\n"
        "- **1-5% loss** - Minor issue, monitor closely\n"
        "- **>5% loss** - Significant problem, investigate\n"
        "- **100% loss** - Host down, firewall blocking, or routing issue\n\n"
        "**Latency benchmarks:**\n"
        "- LAN: < 1ms\n"
        "- Same city: 1-10ms\n"
        "- Same country: 10-50ms\n"
        "- Cross-continent: 50-150ms\n"
        "- Satellite: 500-700ms\n\n"
        "**If ping fails:**\n"
        "1. Check if target has ICMP blocked\n"
        "2. Verify routing with `ip route get target`\n"
        "3. Check local firewall rules\n"
        "4. Try traceroute to find where it fails",
        ["What is acceptable packet loss?", "Ping works but app doesn't?", "How to test MTU?"]
    ),
    "router": (
        "**Router Troubleshooting & Concepts:**\n\n"
        "**Diagnosing router issues:**\n"
        "1. Check interface utilization and error counters\n"
        "2. Review CPU and memory usage\n"
        "3. Check routing table: `show ip route` or `ip route`\n"
        "4. Verify QoS policies\n"
        "5. Look for duplex mismatches\n\n"
        "**Routing protocols:**\n"
        "- **OSPF** - Link-state, fast convergence, areas\n"
        "- **BGP** - Internet backbone, path-vector\n"
        "- **Static routes** - Simple, predictable\n"
        "- **RIP** - Legacy, distance-vector",
        ["How to configure OSPF?", "Static vs dynamic routing?", "Router CPU troubleshooting"]
    ),
    "switch": (
        "**Switching Concepts:**\n\n"
        "- **MAC address table** - Maps MACs to ports\n"
        "- **STP (Spanning Tree)** - Prevents loops, elects root bridge\n"
        "- **Port security** - Limit MACs per port\n"
        "- **LACP** - Link aggregation for redundancy/bandwidth\n"
        "- **Storm control** - Prevent broadcast storms\n\n"
        "**Show commands:**\n"
        "```\n"
        "show mac address-table\n"
        "show spanning-tree\n"
        "show interfaces status\n"
        "```",
        ["How does STP work?", "Port security setup", "LACP configuration"]
    ),
    "wifi": (
        "**Wireless Networking:**\n\n"
        "- **WPA3** - Latest security standard\n"
        "- **802.11ax (Wi-Fi 6)** - Better in dense environments\n"
        "- **Channel planning** - Use 1, 6, 11 for 2.4GHz; non-overlapping for 5GHz\n"
        "- **Band steering** - Push clients to 5GHz when possible\n\n"
        "**Troubleshooting:**\n"
        "1. Check for channel interference\n"
        "2. Verify signal strength (-67dBm or better)\n"
        "3. Check client count per AP\n"
        "4. Review for rogue APs",
        ["Best Wi-Fi channel?", "Improve Wi-Fi performance", "Enterprise Wi-Fi setup"]
    ),
    "ip_addressing": (
        "**IP Addressing Essentials:**\n\n"
        "**Private IP ranges (RFC 1918):**\n"
        "- 10.0.0.0/8 (10.0.0.0 - 10.255.255.255)\n"
        "- 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)\n"
        "- 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)\n\n"
        "**DHCP basics:**\n"
        "- Assigns IP, gateway, DNS, and lease time\n"
        "- DORA: Discover, Offer, Request, Acknowledge\n"
        "- Reserve IPs for servers and network devices\n\n"
        "**IPv6:** Link-local starts with `fe80::`, GUA with `2xxx::`",
        ["DHCP best practices?", "IPv6 transition guide", "IP conflict resolution"]
    ),
    "tls": (
        "**TLS/SSL & Certificates:**\n\n"
        "**Get free certificates:**\n"
        "- Let's Encrypt with certbot\n"
        "- `certbot certonly --standalone -d example.com`\n\n"
        "**Self-signed for internal use:**\n"
        "```\n"
        "openssl req -x509 -newkey rsa:4096 -keyout key.pem \\\n"
        "  -out cert.pem -days 365 -nodes\n"
        "```\n\n"
        "**Best practices:**\n"
        "- Minimum TLS 1.2, prefer TLS 1.3\n"
        "- Strong cipher suites\n"
        "- HSTS header\n"
        "- Certificate pinning for APIs",
        ["How to set up Let's Encrypt?", "TLS vs SSL difference?", "Certificate chain explained"]
    ),
    "backup": (
        "**Backup & Disaster Recovery:**\n\n"
        "**3-2-1 Rule:**\n"
        "- 3 copies of data\n"
        "- 2 different media types\n"
        "- 1 offsite/cloud copy\n\n"
        "**Tools:**\n"
        "- `rsync` - File sync\n"
        "- `borgbackup` - Dedup backup\n"
        "- `restic` - Cloud-native backup\n"
        "- Proxmox Backup Server\n"
        "- Veeam (enterprise)\n\n"
        "**Network config backup:**\n"
        "- RANCID / Oxidized for switch/router configs\n"
        "- Git for version control",
        ["Automate network backups?", "Best backup schedule?", "Test disaster recovery"]
    ),
    "bandwidth": (
        "**Bandwidth Testing & Optimization:**\n\n"
        "**iperf3** - The standard for LAN testing:\n"
        "```\n"
        "# Server: iperf3 -s\n"
        "# Client: iperf3 -c server_ip\n"
        "# Bidirectional: iperf3 -c server_ip --bidir\n"
        "# UDP test: iperf3 -c server_ip -u -b 1G\n"
        "```\n\n"
        "**Common bottlenecks:**\n"
        "- Duplex mismatch (check with `ethtool`)\n"
        "- MTU issues (test with `ping -s 1472 -M do target`)\n"
        "- QoS misconfiguration\n"
        "- ISP throttling",
        ["How to test bandwidth?", "Fix duplex mismatch", "QoS configuration guide"]
    ),
    "logging": (
        "**Centralized Logging:**\n\n"
        "**Stack options:**\n"
        "- **ELK** (Elasticsearch + Logstash + Kibana)\n"
        "- **Graylog** - Full-featured, easy setup\n"
        "- **Loki + Grafana** - Lightweight, label-based\n\n"
        "**Syslog setup:**\n"
        "```\n"
        "# rsyslog - receive remote logs\n"
        "# /etc/rsyslog.conf\n"
        "module(load=\"imudp\")\n"
        "input(type=\"imudp\" port=\"514\")\n"
        "```\n\n"
        "**What to log:**\n"
        "- Auth events (login success/fail)\n"
        "- Firewall deny rules\n"
        "- Interface up/down\n"
        "- Config changes",
        ["Set up Graylog?", "Syslog best practices", "Log retention policy"]
    ),
}


def get_ai_response(message: str, user_id: int, context: Optional[str] = None) -> tuple[str, List[str]]:
    ai_config = _ai_settings.get(user_id)

    if ai_config and ai_config.enabled and ai_config.api_key:
        try:
            return _call_external_ai(message, ai_config, context)
        except Exception as exc:
            logger.warning("External AI call failed: %s", exc)

    return _fallback_response(message)


def _fallback_response(message: str) -> tuple[str, list[str]]:
    topic = _match_topic(message)

    if topic == "nmap":
        return _get_nmap_response(message)
    elif topic == "slow_network":
        return NETWORK_KNOWLEDGE["troubleshooting"]["slow network"], ["How to identify the slow device?", "What causes high latency?", "How to check bandwidth?"]
    elif topic == "connectivity":
        return NETWORK_KNOWLEDGE["troubleshooting"]["connectivity"], ["How to check if a port is blocked?", "What if ping works but app doesn't?"]
    elif topic == "dns":
        return NETWORK_KNOWLEDGE["troubleshooting"]["dns issues"], ["What DNS servers should I use?", "How to flush DNS cache?"]
    elif topic == "security":
        return NETWORK_KNOWLEDGE["security"]["hardening"], ["What ports should I close?", "How to set up network segmentation?"]
    elif topic == "ports":
        return NETWORK_KNOWLEDGE["security"]["ports"], ["Which ports are dangerous?", "How to close unnecessary ports?"]
    elif topic in GENERAL_KNOWLEDGE:
        entry = GENERAL_KNOWLEDGE[topic]
        return entry[0], entry[1]
    elif topic in EXTENDED_TOPICS:
        entry = EXTENDED_TOPICS[topic]
        return entry[0], entry[1]
    elif topic is not None:
        return _general_answer(message)
    else:
        return _general_answer(message)


def _general_answer(message: str) -> tuple[str, list[str]]:
    msg_lower = message.lower()

    greetings = ["hello", "hi", "hey", "good morning", "good afternoon", "good evening", "howdy", "sup", "what's up"]
    if any(g in msg_lower for g in greetings):
        return (
            "Hey there! I'm your NetPulse AI assistant. I can help with pretty much anything - "
            "networking, scripting, troubleshooting, security, home lab setups, and more.\n\n"
            "What's on your mind?",
            ["How to scan my network?", "Home lab setup advice", "Python automation tips"]
        )

    thanks = ["thank", "thanks", "thx", "appreciate", "cheers"]
    if any(t in msg_lower for t in thanks):
        return (
            "You're welcome! Let me know if there's anything else I can help with.",
            ["Any other questions?", "Show me scanning tips", "Network security advice"]
        )

    if "help" in msg_lower or "what can you" in msg_lower or "who are you" in msg_lower:
        return (
            "I'm your NetPulse AI assistant! Here's what I can help with:\n\n"
            "**Networking:**\n"
            "- Scanning (nmap, vulnerability assessment)\n"
            "- Troubleshooting (connectivity, DNS, slow networks)\n"
            "- Subnetting, VLANs, routing, switching\n"
            "- Firewalls, VPNs, Wi-Fi\n\n"
            "**Infrastructure:**\n"
            "- Home lab design and setup\n"
            "- Proxmox, Docker, virtualization\n"
            "- Monitoring (Grafana, Zabbix, SNMP)\n"
            "- Backup and disaster recovery\n\n"
            "**Development:**\n"
            "- Python network automation\n"
            "- Wireshark / packet analysis\n"
            "- TLS/SSL certificates\n"
            "- Logging and observability\n\n"
            "Just ask me anything!",
            ["Scan my network", "Home lab architecture", "Automate with Python"]
        )

    if "?" in message or len(message.split()) > 3:
        return (
            f"That's a great question! Here's what I can share:\n\n"
            f"While I don't have a specific article on \"{message[:80]}{'...' if len(message) > 80 else ''}\", "
            f"I can help you explore this topic. Here are some angles I can cover:\n\n"
            f"1. **Practical how-to** - Step-by-step instructions\n"
            f"2. **Best practices** - Industry recommendations\n"
            f"3. **Troubleshooting** - Common issues and fixes\n"
            f"4. **Tool recommendations** - Open source and commercial options\n\n"
            f"Could you tell me a bit more about what you're trying to accomplish? "
            f"The more context you give me, the better I can help.\n\n"
            f"*Tip: For more detailed AI responses, configure an AI provider in Settings > AI Assistant.*",
            ["Tell me about networking basics", "Home lab setup guide", "Security best practices"]
        )

    return (
        "I'm here to help! I know a lot about networking, security, infrastructure, and automation. "
        "Ask me anything - the more specific your question, the better I can answer.\n\n"
        "Here are some ideas to get started:",
        ["How do I scan my network?", "Set up a home lab", "Python network scripts", "Firewall best practices"]
    )


def _call_external_ai(message: str, config: AISettings, context: Optional[str]) -> tuple[str, List[str]]:
    import httpx

    system_prompt = (
        "You are a knowledgeable AI assistant for NetPulse Enterprise, a comprehensive network monitoring "
        "and security platform. You can answer ANY question the user asks - you are not limited to networking topics. "
        "Be helpful, thorough, and conversational.\n\n"
        "**NetPulse Platform Context:**\n"
        "NetPulse provides: network scanning (nmap integration), device discovery & management, "
        "SNMP polling & monitoring, syslog collection, packet captures, uptime monitoring, "
        "vulnerability assessment, device blocking/quarantining, automated playbooks, "
        "Python script execution, and network topology visualization.\n\n"
        "**Your deep expertise includes:**\n"
        "- **Scanning & Reconnaissance:** nmap scan types (SYN, TCP, UDP, ACK, FIN), NSE scripts "
        "(vuln, auth, brute, discovery, safe categories), scan interpretation (open/closed/filtered ports), "
        "service and OS detection, vulnerability assessment\n"
        "- **NSE Scripts:** Explain what each script does, recommend scripts for specific goals "
        "(e.g., http-title, ssl-enum-ciphers, smb-os-discovery, dns-brute, vuln category), "
        "script arguments and customization\n"
        "- **Incident Response:** Suggest response actions for scan findings, guide through "
        "blocking/quarantining compromised devices (iptables, switch port shutdown, quarantine VLANs, ACLs), "
        "threat investigation workflows\n"
        "- **Network Troubleshooting:** Step-by-step guidance for ping, traceroute/mtr, DNS lookups "
        "(nslookup, dig), bandwidth testing (iperf3), interface diagnostics, MTU issues, routing problems\n"
        "- **SNMP:** OIDs, MIBs, community strings, SNMPv3 configuration, polling intervals, "
        "common OIDs for CPU/memory/interface metrics, snmpwalk/snmpget commands\n"
        "- **Syslog:** RFC 5424 severity levels (0-Emergency to 7-Debug), facility codes, "
        "log patterns to watch (failed auth, link flapping, config changes), rsyslog configuration, "
        "centralized logging setup\n"
        "- **Security:** Network hardening, firewall rules, VPNs, TLS/SSL, port security, VLAN segmentation\n"
        "- **Infrastructure:** Servers, virtualization (Proxmox, VMware), containers (Docker, K8s), cloud\n"
        "- **Automation:** Python (netmiko, paramiko, scapy, pysnmp), scripting, REST APIs, CI/CD\n\n"
        "But you can also help with general knowledge, programming, math, writing, and any other topic.\n\n"
        "**Guidelines:**\n"
        "- Be concise but thorough\n"
        "- Include specific commands, code, or steps when relevant\n"
        "- Use markdown formatting for readability\n"
        "- If you include code, wrap it in code blocks\n"
        "- When discussing scan results, explain what each finding means and suggest remediation\n"
        "- When recommending nmap commands, include relevant flags and explain their purpose\n"
        "- When discussing NSE scripts, explain what they detect and when to use them\n"
        "- At the end, suggest 2-3 follow-up questions the user might want to ask"
    )

    user_content = message
    if context:
        user_content = f"Context: {context}\n\nQuestion: {message}"

    if config.provider == "openai" or config.provider in ("groq", "together", "custom"):
        base_url = "https://api.openai.com/v1/chat/completions"
        if config.provider == "groq":
            base_url = "https://api.groq.com/openai/v1/chat/completions"
        elif config.provider == "together":
            base_url = "https://api.together.xyz/v1/chat/completions"
        elif config.provider == "custom" and config.custom_base_url:
            base_url = config.custom_base_url.rstrip("/") + "/chat/completions"

        model = config.model
        if config.provider == "custom" and config.custom_model:
            model = config.custom_model

        response = httpx.post(
            base_url,
            headers={"Authorization": f"Bearer {config.api_key}"},
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content},
                ],
                "max_tokens": 1000,
            },
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        choices = data.get("choices")
        if not choices:
            raise ValueError("No choices in AI response")
        ai_response = choices[0]["message"]["content"]
        return ai_response, ["Tell me more", "What else should I know?", "Can you give an example?"]

    elif config.provider == "anthropic":
        response = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": config.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": config.model,
                "max_tokens": 1000,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_content}],
            },
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        content_blocks = data.get("content", [])
        ai_response = " ".join(b.get("text", "") for b in content_blocks if b.get("type") == "text")
        return ai_response, ["Tell me more", "What else should I know?", "Can you give an example?"]

    elif config.provider == "google":
        response = httpx.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{config.model}:generateContent?key={config.api_key}",
            json={
                "contents": [{"parts": [{"text": f"{system_prompt}\n\n{user_content}"}]}],
                "generationConfig": {"maxOutputTokens": 1000},
            },
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        candidates = data.get("candidates", [])
        if candidates:
            parts = candidates[0].get("content", {}).get("parts", [])
            ai_response = " ".join(p.get("text", "") for p in parts)
            return ai_response, ["Tell me more", "What else should I know?", "Can you give an example?"]
        raise ValueError("No candidates in Google AI response")

    elif config.provider == "ollama":
        base_url = config.custom_base_url or "http://localhost:11434"
        response = httpx.post(
            f"{base_url.rstrip('/')}/api/chat",
            json={
                "model": config.model or config.custom_model or "llama3.1",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content},
                ],
                "stream": False,
            },
            timeout=60,
        )
        response.raise_for_status()
        data = response.json()
        ai_response = data.get("message", {}).get("content", "")
        return ai_response, ["Tell me more", "What else should I know?", "Can you give an example?"]

    raise NotImplementedError(f"Provider {config.provider} not yet supported for chat")


@router.post(
    "/chat",
    response_model=ChatResponse,
    summary="Send a message to the AI assistant",
)
async def chat(
    request: ChatRequest,
    current_user: User = Depends(get_current_user),
) -> ChatResponse:
    response, suggestions = get_ai_response(
        request.message,
        current_user.id,
        request.context,
    )
    return ChatResponse(response=response, suggestions=suggestions)


@router.get(
    "/suggestions",
    summary="Get conversation starters",
)
async def get_suggestions(
    current_user: User = Depends(get_current_user),
) -> List[str]:
    return [
        "How do I scan my network for vulnerabilities?",
        "Help me set up a home lab",
        "What's the best way to secure my network?",
        "Python script for network automation",
        "Explain subnetting to me",
        "How to troubleshoot slow Wi-Fi?",
    ]


class FileAnalysisResponse(BaseModel):
    response: str
    file_name: str
    file_type: str
    file_size: int
    suggestions: List[str]


def _analyze_file_content(filename: str, content: bytes) -> tuple[str, List[str]]:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "unknown"
    size = len(content)

    if ext == "pcap":
        return (
            f"I've received your packet capture file '{filename}' ({size:,} bytes). "
            "This is a PCAP file that can be analyzed with Wireshark or tshark. "
            "To analyze it:\n\n"
            "1. **Protocol distribution**: `tshark -r file.pcap -qz io,phs`\n"
            "2. **Top talkers**: `tshark -r file.pcap -qz conv,ip`\n"
            "3. **HTTP requests**: `tshark -r file.pcap -Y 'http.request'`\n"
            "4. **DNS queries**: `tshark -r file.pcap -Y 'dns.flags.response == 0'`\n\n"
            "Would you like me to help you analyze specific aspects of this capture?",
            ["Show me suspicious traffic", "Find DNS queries", "Analyze HTTP traffic", "Look for port scans"]
        )

    elif ext in ("log", "txt"):
        try:
            text = content.decode("utf-8", errors="ignore")
            lines = text.splitlines()
            error_count = sum(1 for line in lines if "error" in line.lower())
            warn_count = sum(1 for line in lines if "warn" in line.lower())

            analysis = (
                f"I've analyzed your log file '{filename}' ({size:,} bytes, {len(lines):,} lines).\n\n"
                f"**Quick Stats:**\n"
                f"- Total lines: {len(lines):,}\n"
                f"- Error entries: {error_count}\n"
                f"- Warning entries: {warn_count}\n\n"
            )

            if error_count > 0:
                analysis += "I found some errors in the log. Would you like me to help troubleshoot them?"
            else:
                analysis += "No obvious errors detected. Would you like me to look for specific patterns?"

            return analysis, ["Show error details", "Find patterns", "Summarize activity", "Look for security issues"]
        except Exception:
            return f"Received log file '{filename}' ({size:,} bytes). Unable to parse content.", []

    elif ext == "json":
        try:
            import json
            data = json.loads(content.decode("utf-8"))
            if isinstance(data, list):
                return (
                    f"I've received a JSON file '{filename}' containing an array with {len(data)} items. "
                    "Would you like me to help analyze the structure or find specific data?",
                    ["Summarize the data", "Find anomalies", "Extract specific fields"]
                )
            elif isinstance(data, dict):
                return (
                    f"I've received a JSON file '{filename}' with {len(data)} top-level keys. "
                    "Would you like me to help analyze the configuration or data?",
                    ["Explain the structure", "Validate the config", "Find issues"]
                )
        except Exception:
            return f"Received JSON file '{filename}' ({size:,} bytes) but couldn't parse it.", []

    return (
        f"I've received your file '{filename}' ({size:,} bytes). "
        "I can help you analyze network captures (PCAP), log files, and configuration files. "
        "What would you like to know about this file?",
        ["What's in this file?", "Help me analyze it"]
    )


@router.post(
    "/upload",
    response_model=FileAnalysisResponse,
    summary="Upload a file for AI analysis",
)
async def upload_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
) -> FileAnalysisResponse:
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in ALLOWED_FILE_TYPES and ext not in ("pcap", "log", "txt", "json", "csv"):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {ext}. Allowed: pcap, log, txt, json, csv"
        )

    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size: {MAX_FILE_SIZE // (1024*1024)}MB"
        )

    response, suggestions = _analyze_file_content(file.filename, content)

    return FileAnalysisResponse(
        response=response,
        file_name=file.filename,
        file_type=ext,
        file_size=len(content),
        suggestions=suggestions,
    )
