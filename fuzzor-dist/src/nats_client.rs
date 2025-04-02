use async_nats::{
    client::Client,
    jetstream::{
        self, consumer::Consumer, context::PublishAckFuture, object_store, stream, Message,
    },
};
use futures::stream::{FuturesUnordered, StreamExt};
use serde::{de::DeserializeOwned, Serialize};
use std::{net::SocketAddr, time::Duration};

use crate::{coordinator::FuzzorMsg, workers::WorkerInfo};

#[derive(Debug)]
pub enum NatsError {
    FailedToConnectToServer(String),
    OperationFailed(String),
    SerializationError(String),
    DeserializationError(String),
    PublishError(String),
    AckError(String),
    FetchError(String),
}

impl std::fmt::Display for NatsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatsError::FailedToConnectToServer(msg) => {
                write!(f, "Failed to connect to NATS server: {}", msg)
            }
            NatsError::OperationFailed(msg) => write!(f, "NATS operation failed: {}", msg),
            NatsError::SerializationError(msg) => write!(f, "Serialization failed: {}", msg),
            NatsError::DeserializationError(msg) => write!(f, "Deserialization failed: {}", msg),
            NatsError::PublishError(msg) => write!(f, "Publish failed: {}", msg),
            NatsError::AckError(msg) => write!(f, "Ack operation failed: {}", msg),
            NatsError::FetchError(msg) => write!(f, "Fetch failed: {}", msg),
        }
    }
}

impl std::error::Error for NatsError {}

#[derive(Debug, Clone)]
pub struct FuzzorNatsClient {
    addr: SocketAddr,
    client: Client,
    js_ctx: jetstream::Context,
}

impl FuzzorNatsClient {
    pub async fn new(nats_server: SocketAddr) -> Result<Self, NatsError> {
        let nats_url = format!("nats://{}", nats_server);
        log::debug!("Connecting to NATS at {}...", nats_url);

        let client = async_nats::connect(&nats_url)
            .await
            .map_err(|e| NatsError::FailedToConnectToServer(e.to_string()))?;

        log::debug!(
            "New NATS client successfully connected to NATS at {}",
            nats_url
        );
        let js_ctx = jetstream::new(client.clone());

        Ok(Self {
            addr: nats_server,
            client,
            js_ctx,
        })
    }

    pub async fn wait_for_stream(&self, stream_name: &str) -> Result<stream::Stream, NatsError> {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            match self.js_ctx.get_stream(stream_name).await {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    log::error!("Failed to get stream '{}': {}", stream_name, e);
                    interval.tick().await;
                }
            }
        }
    }

    /// Gets or creates a JetStream stream with the given configuration.
    pub async fn get_or_create_stream(
        &self,
        config: stream::Config,
    ) -> Result<stream::Stream, NatsError> {
        let stream_name = config.name.clone();
        log::debug!("Getting or creating stream '{}'...", stream_name);
        self.js_ctx.get_or_create_stream(config).await.map_err(|e| {
            NatsError::OperationFailed(format!(
                "Failed to get or create stream '{}': {}",
                stream_name, e
            ))
        })
    }

    /// Gets an existing JetStream stream.
    pub async fn get_stream(&self, stream_name: &str) -> Result<stream::Stream, NatsError> {
        log::debug!("Getting stream '{}'...", stream_name);
        self.js_ctx.get_stream(stream_name).await.map_err(|e| {
            NatsError::OperationFailed(format!("Failed to get stream '{}': {}", stream_name, e))
        })
    }

    /// Gets or creates a JetStream object store with the given configuration.
    pub async fn get_or_create_object_store(
        &self,
        config: object_store::Config,
    ) -> Result<object_store::ObjectStore, NatsError> {
        let store_name = config.bucket.clone();
        log::debug!("Getting or creating object store '{}'...", store_name);
        self.js_ctx.create_object_store(config).await.map_err(|e| {
            NatsError::OperationFailed(format!(
                "Failed to get or create object store '{}': {}",
                store_name, e
            ))
        })
    }

    /// Gets an existing JetStream object store.
    pub async fn get_object_store(
        &self,
        store_name: &str,
    ) -> Result<object_store::ObjectStore, NatsError> {
        log::debug!("Getting object store '{}'...", store_name);
        self.js_ctx.get_object_store(store_name).await.map_err(|e| {
            NatsError::OperationFailed(format!(
                "Failed to get object store '{}': {}",
                store_name, e
            ))
        })
    }

    /// Serializes and publishes a `FuzzorMsg` to the given subject.
    ///
    /// Returns the `PublishAckFuture` which should be awaited to confirm delivery.
    pub async fn publish_fuzzor_msg<P>(
        &self,
        subject: String,
        payload: P,
        correlation_id: Option<String>,
        worker_info: Option<WorkerInfo>,
    ) -> Result<PublishAckFuture, NatsError>
    where
        P: Serialize,
    {
        log::debug!(
            "Publishing message to subject '{}', correlation_id: {:?}, worker_info: {:?}",
            subject,
            correlation_id,
            worker_info
        );
        let msg = FuzzorMsg {
            payload,
            correlation_id,
            worker_info,
        };

        let bytes =
            serde_json::to_vec(&msg).map_err(|e| NatsError::SerializationError(e.to_string()))?;

        self.js_ctx
            .publish(subject.clone(), bytes.into())
            .await
            .map_err(|e| {
                NatsError::PublishError(format!("Failed to publish to '{}': {}", subject, e))
            })
    }

    /// Serializes, publishes, and waits for the acknowledgment of a `FuzzorMsg`.
    pub async fn publish_fuzzor_msg_and_wait<P>(
        &self,
        subject: String,
        payload: P,
        correlation_id: Option<String>,
        worker_info: Option<WorkerInfo>,
    ) -> Result<(), NatsError>
    where
        P: Serialize,
    {
        let ack_future = self
            .publish_fuzzor_msg(subject.clone(), payload, correlation_id, worker_info)
            .await?;
        ack_future.await.map_err(|e| {
            NatsError::AckError(format!("Failed to await ack for '{}': {}", subject, e))
        })?;
        Ok(())
    }

    /// Fetches the next message from a pull consumer within a timeout, acknowledges it,
    /// and attempts to deserialize it into a `FuzzorMsg<P>`.
    ///
    /// Returns `Ok(None)` if no message arrives within the timeout.
    /// Returns `Err(NatsError::DeserializationError)` if the message payload cannot be deserialized.
    /// Returns other `Err(NatsError)` variants for NATS communication issues.
    pub async fn fetch_next_fuzzor_msg<P>(
        &self,
        consumers: &[&Consumer<jetstream::consumer::pull::Config>],
        timeout: Duration,
    ) -> Result<Option<(FuzzorMsg<P>, Message)>, NatsError>
    where
        P: DeserializeOwned,
    {
        log::trace!(
            "Fetching next message from {} consumers with timeout {:?}...",
            consumers.len(),
            timeout
        );

        if consumers.is_empty() {
            log::warn!("fetch_next_fuzzor_msg called with no consumers.");
            return Ok(None);
        }

        let mut message_streams = Vec::with_capacity(consumers.len());

        // Phase 1: Initiate fetch and get message streams for all consumers
        for consumer in consumers {
            let messages_result = consumer
                .fetch()
                .max_messages(1) // Still fetch max 1 per consumer initially
                .expires(timeout) // Apply timeout to the initial fetch request
                .messages()
                .await;

            match messages_result {
                Ok(stream) => {
                    message_streams.push(stream.fuse()); // fuse() helps manage ended streams
                }
                Err(e) => {
                    // If getting the stream itself fails for any consumer, return an error
                    log::error!("Failed to fetch messages for a consumer: {}", e);
                    return Err(NatsError::FetchError(format!(
                        "Failed to initiate fetch: {}",
                        e
                    )));
                }
            }
        }

        // Phase 2: Wait for the *next* message from any of the streams
        let mut next_message_futures = FuturesUnordered::new();
        for stream in message_streams.iter_mut() {
            // Each stream's next() call becomes a future in the set
            next_message_futures.push(stream.next());
        }

        // Now, wait for the first future in the set to complete
        while let Some(message_result_option) = next_message_futures.next().await {
            match message_result_option {
                Some(Ok(message)) => {
                    // First message received!
                    log::trace!(
                        "Received message on subject '{}', attempting ack...",
                        message.subject
                    );
                    // Explicitly drop the FuturesUnordered to cancel other pending next() futures.
                    drop(next_message_futures);

                    message.ack().await.map_err(|e| {
                        NatsError::AckError(format!("Failed to ack message: {}", e))
                    })?;
                    log::trace!("Message acknowledged. Deserializing...");

                    match serde_json::from_slice::<FuzzorMsg<P>>(&message.payload) {
                        Ok(fuzzor_msg) => {
                            log::trace!("Deserialization successful.");
                            return Ok(Some((fuzzor_msg, message))); // Return success
                        }
                        Err(e) => {
                            log::error!("Failed to deserialize message payload: {}", e);
                            // Deserialization failed for the first message received.
                            return Err(NatsError::DeserializationError(e.to_string()));
                        }
                    }
                }
                Some(Err(e)) => {
                    // An error occurred while polling one of the streams
                    log::error!("Error receiving message from stream: {}", e);
                    // Decide how to handle this. Return the error for now.
                    // Could potentially log and continue waiting on others, but complexity increases.
                    return Err(NatsError::FetchError(format!(
                        "Error polling message stream: {}",
                        e
                    )));
                }
                None => {
                    // One of the streams ended without producing a message.
                    // This happens if the stream times out or closes gracefully.
                    // We just continue the loop, waiting for other streams in FuturesUnordered.
                    log::trace!("One message stream finished without yielding a message.");
                }
            }
        }

        // If the loop completes, all streams finished without yielding a message.
        log::trace!(
            "All message streams finished or timed out after {:?}. No message received.",
            timeout
        );
        Ok(None)
    }

    /// Provides access to the raw JetStream context if needed.
    pub fn jetstream_context(&self) -> &jetstream::Context {
        &self.js_ctx
    }

    /// Provides access to the raw NATS client if needed.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Returns the address of the NATS server.
    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }
}
