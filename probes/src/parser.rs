use chrono::Utc;
use pnet_packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    Packet,
};
use std::env;
use std::sync::OnceLock;

use crate::event::PacketEvent;

/// Get the list of excluded TCP ports from environment variable or use defaults.
/// Defaults to TCP ports 2575 (HL7), 104 (DICOM), and 2762 (DICOM-TLS).
/// Can be overridden via EXCLUDED_PORTS environment variable (comma-separated).
fn get_excluded_ports() -> &'static Vec<u16> {
    static EXCLUDED_PORTS: OnceLock<Vec<u16>> = OnceLock::new();
    EXCLUDED_PORTS.get_or_init(|| {
        if let Ok(env_var) = env::var("EXCLUDED_PORTS") {
            env_var
                .split(',')
                .filter_map(|s| s.trim().parse::<u16>().ok())
                .collect()
        } else {
            // Default fragile device ports
            vec![2575, 104, 2762]
        }
    })
}

/// Generate a BPF deny-list filter that excludes fragile device ports.
/// This filter drops packets on fragile/restricted device ports before
/// they reach userspace — prevents passive capture from interfering with
/// critical devices.
pub fn get_fragile_device_bpf_filter() -> String {
    let ports = get_excluded_ports();
    if ports.is_empty() {
        // If no ports are excluded, return a filter that allows everything
        // Using "tcp or udp" is more explicit than "not (tcp port 0)"
        "tcp or udp".to_string()
    } else {
        let port_conditions = ports
            .iter()
            .map(|p| format!("tcp port {}", p))
            .collect::<Vec<_>>()
            .join(" or ");
        format!("not ({})", port_conditions)
    }
}

/// Legacy constant name for backward compatibility.
/// 
/// **NOTE**: This constant uses hardcoded ports and will NOT reflect custom EXCLUDED_PORTS
/// environment variable values. Use get_fragile_device_bpf_filter() at runtime to get
/// the configured BPF filter that respects EXCLUDED_PORTS. This constant is provided
/// only for legacy compatibility and should be avoided in new code.
pub const FRAGILE_DEVICE_BPF_FILTER: &str =
    "not (tcp port 2575 or tcp port 104 or tcp port 2762)";

/// Parse a raw libpcap frame into a [`PacketEvent`].
/// Returns `None` if the frame is too short to contain an Ethernet header.
pub fn parse_raw_frame_into_packet_event(raw_frame: &[u8]) -> Option<PacketEvent> {
    let ethernet_frame = EthernetPacket::new(raw_frame)?;

    let mut event = PacketEvent {
        timestamp: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
        source_mac: ethernet_frame.get_source().to_string(),
        destination_mac: ethernet_frame.get_destination().to_string(),
        payload_length_bytes: raw_frame.len(),
        ..Default::default()
    };

    match ethernet_frame.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_frame.payload()) {
                event.source_ip = ipv4_packet.get_source().to_string();
                event.destination_ip = ipv4_packet.get_destination().to_string();
                event.protocol = format!("{:?}", ipv4_packet.get_next_level_protocol());
                populate_transport_ports(
                    &mut event,
                    ipv4_packet.get_next_level_protocol(),
                    ipv4_packet.payload(),
                );
            }
        }
        EtherTypes::Ipv6 => {
            if let Some(ipv6_packet) = Ipv6Packet::new(ethernet_frame.payload()) {
                event.source_ip = ipv6_packet.get_source().to_string();
                event.destination_ip = ipv6_packet.get_destination().to_string();
                event.protocol = format!("{:?}", ipv6_packet.get_next_header());
                populate_transport_ports(
                    &mut event,
                    ipv6_packet.get_next_header(),
                    ipv6_packet.payload(),
                );
            }
        }
        _ => {}
    }

    Some(event)
}

fn populate_transport_ports(
    event: &mut PacketEvent,
    next_header_protocol: pnet_packet::ip::IpNextHeaderProtocol,
    transport_payload: &[u8],
) {
    match next_header_protocol {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp_segment) = TcpPacket::new(transport_payload) {
                event.source_port = tcp_segment.get_source();
                event.destination_port = tcp_segment.get_destination();
            }
        }
        IpNextHeaderProtocols::Udp => {
            if let Some(udp_datagram) = UdpPacket::new(transport_payload) {
                event.source_port = udp_datagram.get_source();
                event.destination_port = udp_datagram.get_destination();
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bpf_deny_filter_contains_all_fragile_device_ports() {
        let filter = get_fragile_device_bpf_filter();
        for protected_port in &["2575", "104", "2762"] {
            assert!(
                filter.contains(protected_port),
                "BPF deny-filter must reference fragile device port {protected_port}",
            );
        }
    }

    #[test]
    fn bpf_deny_filter_uses_negation() {
        let filter = get_fragile_device_bpf_filter();
        assert!(
            filter.contains("not"),
            "BPF filter must contain 'not' to exclude fragile device ports",
        );
    }

    #[test]
    fn malformed_frame_returns_none() {
        assert!(
            parse_raw_frame_into_packet_event(&[0u8; 4]).is_none(),
            "frames shorter than an Ethernet header must return None",
        );
    }
}
