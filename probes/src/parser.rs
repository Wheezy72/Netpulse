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

use crate::event::PacketEvent;

/// BPF deny-list that drops HL7 (2575), DICOM (104), and DICOM-TLS (2762)
/// at the kernel level before the packet ever reaches userspace.
///
/// WHY a deny-list rather than an allow-list: the probe is a passive observer
/// of general network traffic. Dropping only the medically sensitive ports lets
/// all other traffic flow through while guaranteeing that active probing of
/// medical-grade devices is physically impossible from this path.
pub const MEDICAL_PORT_BPF_DENY_FILTER: &str =
    "not (tcp port 2575 or tcp port 104 or tcp port 2762)";

/// Parse a raw libpcap frame into a [`PacketEvent`].
///
/// Returns `None` only when the frame is so malformed that not even the
/// Ethernet header is parseable — in practice this should never happen on a
/// well-formed interface capture.
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
    fn bpf_deny_filter_contains_all_medical_ports() {
        for protected_port in &["2575", "104", "2762"] {
            assert!(
                MEDICAL_PORT_BPF_DENY_FILTER.contains(protected_port),
                "BPF deny-filter must reference medical/DICOM port {protected_port}",
            );
        }
    }

    #[test]
    fn bpf_deny_filter_uses_negation() {
        assert!(
            MEDICAL_PORT_BPF_DENY_FILTER.contains("not"),
            "BPF filter must contain 'not' to exclude medical ports",
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
