use lapin::{
    options::{BasicPublishOptions, ExchangeDeclareOptions},
    types::FieldTable,
    BasicProperties, Channel, Connection, ConnectionProperties, ExchangeKind,
};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::event::PacketEvent;

const AMQP_EXCHANGE_NAME: &str = "netpulse.telemetry";
const AMQP_ROUTING_KEY: &str = "probe.packet";
const AMQP_MAX_CONNECTION_ATTEMPTS: u32 = 10;
const AMQP_INITIAL_BACKOFF_SECONDS: u64 = 2;
const AMQP_MAX_BACKOFF_SECONDS: u64 = 30;

/// Connect to RabbitMQ and declare the telemetry exchange.
/// Retries up to [`AMQP_MAX_CONNECTION_ATTEMPTS`] times with capped exponential backoff.
pub async fn connect_and_declare_exchange(
    amqp_url: &str,
) -> Result<(Connection, Channel), lapin::Error> {
    let mut last_error: Option<lapin::Error> = None;

    for attempt_number in 1..=AMQP_MAX_CONNECTION_ATTEMPTS {
        match try_connect_and_declare(amqp_url).await {
            Ok(result) => return Ok(result),
            Err(err) => {
                warn!(attempt = attempt_number, max = AMQP_MAX_CONNECTION_ATTEMPTS, error = %err, "AMQP connection failed");
                last_error = Some(err);
                let backoff_seconds = (AMQP_INITIAL_BACKOFF_SECONDS * attempt_number as u64)
                    .min(AMQP_MAX_BACKOFF_SECONDS);
                sleep(Duration::from_secs(backoff_seconds)).await;
            }
        }
    }

    Err(last_error.unwrap())
}

async fn try_connect_and_declare(amqp_url: &str) -> Result<(Connection, Channel), lapin::Error> {
    let connection = Connection::connect(amqp_url, ConnectionProperties::default()).await?;
    let channel = connection.create_channel().await?;

    channel
        .exchange_declare(
            AMQP_EXCHANGE_NAME,
            ExchangeKind::Topic,
            ExchangeDeclareOptions {
                durable: true,
                ..Default::default()
            },
            FieldTable::default(),
        )
        .await?;

    info!(exchange = AMQP_EXCHANGE_NAME, "AMQP exchange declared");
    Ok((connection, channel))
}

/// Serialise a [`PacketEvent`] to JSON and publish it to the telemetry exchange.
pub async fn publish_packet_event(
    channel: &Channel,
    event: &PacketEvent,
) -> Result<(), Box<dyn std::error::Error>> {
    let json_payload = serde_json::to_vec(event)?;

    channel
        .basic_publish(
            AMQP_EXCHANGE_NAME,
            AMQP_ROUTING_KEY,
            BasicPublishOptions::default(),
            &json_payload,
            BasicProperties::default().with_content_type("application/json".into()),
        )
        .await?
        .await?;

    Ok(())
}

/// Log a publish failure without panicking — a dropped message is less harmful than a crash loop.
pub fn log_publish_error(error: &dyn std::error::Error) {
    error!(error = %error, "failed to publish packet event to RabbitMQ");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exchange_name_matches_consumer_expectation() {
        assert_eq!(AMQP_EXCHANGE_NAME, "netpulse.telemetry");
    }

    #[test]
    fn routing_key_matches_consumer_expectation() {
        assert_eq!(AMQP_ROUTING_KEY, "probe.packet");
    }
}
