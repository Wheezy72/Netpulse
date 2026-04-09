mod event;
mod parser;
mod publisher;

use pcap::{Capture, Device};
use tokio::signal;
use tokio::sync::mpsc;
use tracing::{error, info};

use event::PacketEvent;
use parser::{parse_raw_frame_into_packet_event, MEDICAL_PORT_BPF_DENY_FILTER};
use publisher::{connect_and_declare_exchange, log_publish_error, publish_packet_event};

/// Default AMQP URL used when `RABBITMQ_URL` is not set in the environment.
const DEFAULT_RABBITMQ_URL: &str = "amqp://netpulse:netpulse@localhost:5672/netpulse";

/// Default network interface used when `PROBE_IFACE` is not set.
const DEFAULT_CAPTURE_INTERFACE: &str = "eth0";

/// Internal channel capacity. Back-pressure here means the capture thread
/// briefly blocks rather than dropping frames silently.
const PACKET_CHANNEL_BUFFER_SIZE: usize = 4096;

/// Read an environment variable, returning the fallback value when the
/// variable is unset or empty — identical semantics to the Go probe's
/// `mustGetenv`.
fn read_env_or_fallback(variable_name: &str, fallback_value: &str) -> String {
    match std::env::var(variable_name) {
        Ok(value) if !value.is_empty() => value,
        _ => fallback_value.to_owned(),
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let rabbitmq_url = read_env_or_fallback("RABBITMQ_URL", DEFAULT_RABBITMQ_URL);
    let capture_interface_name = read_env_or_fallback("PROBE_IFACE", DEFAULT_CAPTURE_INTERFACE);

    let capture_device = Device::list()
        .unwrap_or_default()
        .into_iter()
        .find(|device| device.name == capture_interface_name)
        .unwrap_or_else(|| Device {
            name: capture_interface_name.clone(),
            desc: None,
            addresses: vec![],
            flags: pcap::DeviceFlags::empty(),
        });

    let mut packet_capture = Capture::from_device(capture_device)
        .expect("failed to open capture device")
        .snaplen(1600)
        .promisc(true)
        .open()
        .expect("failed to activate capture handle");

    packet_capture
        .filter(MEDICAL_PORT_BPF_DENY_FILTER, true)
        .expect("failed to compile and apply BPF deny-filter");

    info!(interface = %capture_interface_name, filter = MEDICAL_PORT_BPF_DENY_FILTER, "probe: capture started");

    let (packet_event_sender, mut packet_event_receiver) =
        mpsc::channel::<PacketEvent>(PACKET_CHANNEL_BUFFER_SIZE);

    // The pcap API is inherently blocking, so capture runs in a dedicated
    // OS thread managed by tokio's blocking thread-pool.
    tokio::task::spawn_blocking(move || {
        loop {
            match packet_capture.next_packet() {
                Ok(raw_frame) => {
                    if let Some(event) = parse_raw_frame_into_packet_event(raw_frame.data) {
                        // Dropping here (when the channel is full) is
                        // intentional: back-pressure shedding is safer than
                        // unbounded memory growth under burst traffic.
                        let _ = packet_event_sender.blocking_send(event);
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(err) => {
                    error!(error = %err, "pcap capture error — exiting capture loop");
                    break;
                }
            }
        }
    });

    let (_amqp_connection, amqp_channel) = connect_and_declare_exchange(&rabbitmq_url)
        .await
        .expect("could not connect to RabbitMQ after retries");

    info!("probe: publishing telemetry to RabbitMQ");

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("probe: received shutdown signal — draining channel and exiting");
                break;
            }
            Some(event) = packet_event_receiver.recv() => {
                if let Err(err) = publish_packet_event(&amqp_channel, &event).await {
                    log_publish_error(err.as_ref());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_env_or_fallback_returns_variable_value_when_set() {
        std::env::set_var("TEST_NP_VAR_SET", "expected_value");
        assert_eq!(
            read_env_or_fallback("TEST_NP_VAR_SET", "fallback"),
            "expected_value"
        );
        std::env::remove_var("TEST_NP_VAR_SET");
    }

    #[test]
    fn read_env_or_fallback_returns_fallback_when_variable_is_unset() {
        std::env::remove_var("TEST_NP_VAR_UNSET");
        assert_eq!(
            read_env_or_fallback("TEST_NP_VAR_UNSET", "fallback_value"),
            "fallback_value"
        );
    }

    #[test]
    fn read_env_or_fallback_returns_fallback_when_variable_is_empty_string() {
        std::env::set_var("TEST_NP_VAR_EMPTY", "");
        assert_eq!(
            read_env_or_fallback("TEST_NP_VAR_EMPTY", "fallback_value"),
            "fallback_value"
        );
        std::env::remove_var("TEST_NP_VAR_EMPTY");
    }

    #[test]
    fn default_rabbitmq_url_is_correct() {
        assert_eq!(
            DEFAULT_RABBITMQ_URL,
            "amqp://netpulse:netpulse@localhost:5672/netpulse"
        );
    }
}
