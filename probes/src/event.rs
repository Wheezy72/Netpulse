use serde::{Deserialize, Serialize};

/// JSON payload published to RabbitMQ for every captured packet.
///
/// Field names match the original Go probe schema exactly so that the Python
/// consumer (which deserialises this JSON) requires no changes.
///
/// Optional fields use `skip_serializing_if` rather than `Option` with
/// `serde(skip_serializing_if = "Option::is_none")` so that the JSON output is
/// identical to the Go `omitempty` behaviour: absent when the underlying value
/// is the zero/empty string or zero integer.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct PacketEvent {
    #[serde(rename = "ts")]
    pub timestamp: String,

    #[serde(rename = "src_mac", default, skip_serializing_if = "String::is_empty")]
    pub source_mac: String,

    #[serde(rename = "dst_mac", default, skip_serializing_if = "String::is_empty")]
    pub destination_mac: String,

    #[serde(rename = "src_ip", default, skip_serializing_if = "String::is_empty")]
    pub source_ip: String,

    #[serde(rename = "dst_ip", default, skip_serializing_if = "String::is_empty")]
    pub destination_ip: String,

    #[serde(rename = "proto", default, skip_serializing_if = "String::is_empty")]
    pub protocol: String,

    #[serde(rename = "src_port", default, skip_serializing_if = "is_zero_u16")]
    pub source_port: u16,

    #[serde(rename = "dst_port", default, skip_serializing_if = "is_zero_u16")]
    pub destination_port: u16,

    /// Always serialised (no skip) — mirrors the Go probe's `payload_len`
    /// field which has no `omitempty` tag.
    #[serde(rename = "payload_len")]
    pub payload_length_bytes: usize,
}

fn is_zero_u16(value: &u16) -> bool {
    *value == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fully_populated_event_serialises_all_fields() {
        let event = PacketEvent {
            timestamp: "2024-01-01T00:00:00Z".into(),
            source_mac: "aa:bb:cc:dd:ee:ff".into(),
            destination_mac: "11:22:33:44:55:66".into(),
            source_ip: "10.0.0.1".into(),
            destination_ip: "10.0.0.2".into(),
            protocol: "TCP".into(),
            source_port: 1234,
            destination_port: 80,
            payload_length_bytes: 512,
        };

        let json = serde_json::to_string(&event).expect("serialisation must succeed");

        for expected_key in &[
            "ts",
            "src_mac",
            "dst_mac",
            "src_ip",
            "dst_ip",
            "proto",
            "src_port",
            "dst_port",
            "payload_len",
        ] {
            assert!(
                json.contains(&format!("\"{}\"", expected_key)),
                "JSON must contain key \"{expected_key}\" but got: {json}",
            );
        }
    }

    #[test]
    fn empty_optional_fields_are_omitted_from_json() {
        let event = PacketEvent {
            payload_length_bytes: 0,
            ..Default::default()
        };

        let json = serde_json::to_string(&event).expect("serialisation must succeed");

        for absent_key in &[
            "src_mac", "dst_mac", "src_ip", "dst_ip", "proto", "src_port", "dst_port",
        ] {
            assert!(
                !json.contains(&format!("\"{}\"", absent_key)),
                "key \"{absent_key}\" must be absent when empty but appeared in: {json}",
            );
        }
    }

    #[test]
    fn payload_len_is_always_present_even_when_zero() {
        let event = PacketEvent::default();
        let json = serde_json::to_string(&event).expect("serialisation must succeed");
        assert!(
            json.contains("\"payload_len\""),
            "payload_len must always be present, got: {json}",
        );
    }

    #[test]
    fn json_round_trip_preserves_all_fields() {
        let original = PacketEvent {
            timestamp: "2024-06-15T12:00:00Z".into(),
            source_ip: "192.168.1.1".into(),
            destination_ip: "8.8.8.8".into(),
            protocol: "UDP".into(),
            source_port: 53000,
            destination_port: 53,
            payload_length_bytes: 64,
            ..Default::default()
        };

        let json = serde_json::to_string(&original).expect("serialisation must succeed");
        let decoded: PacketEvent =
            serde_json::from_str(&json).expect("deserialisation must succeed");

        assert_eq!(decoded, original);
    }
}
