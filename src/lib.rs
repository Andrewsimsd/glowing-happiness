#![warn(clippy::pedantic)]
//! # Glowing Happiness Library
//!
//! ## Overview
//! A lightweight UDP messaging library that wraps datagrams in a typed `PayloadEnvelope`
//! so callers can move text, JSON, or binary file bytes across the network with minimal
//! ceremony. It is intentionally dependency-light and favors predictable, testable
//! behaviors suitable for demos or small control-plane utilities.
//!
//! ## Key Concepts
//! - [`PayloadEnvelope`] defines a forward-compatible container with an explicit version.
//! - [`PayloadKind`] enumerates the supported payload variants.
//! - [`spawn_listener`] runs a background receive loop and forwards decoded frames.
//! - [`send_message`] transmits raw payload bytes over UDP.
//!
//! ## Error Handling
//! All fallible APIs return [`MessengerError`], which documents the concrete operation that
//! failed (bind, send, receive, parse, or serialization). Use the `Display` impls for
//! end-user messages and pattern match when programmatic recovery is required.
//!
//! ## Concurrency Model
//! `spawn_listener` is a thin wrapper over `std::thread::spawn` that reads into a
//! reusable buffer and pushes messages through a `SyncSender`. The caller owns the
//! channel, making backpressure explicit via bounded channels when needed.
//!
//! ## Testing
//! Integration-style unit tests run against loopback sockets to mock Ethernet/UDP traffic
//! without external dependencies. Payload serialization is round-tripped to ensure
//! compatibility, and listener behavior is validated for both graceful shutdown and
//! channel disconnect scenarios.
//!
use std::fmt;
use std::io::{self, ErrorKind};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::mpsc::SyncSender;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// UDP port used by default for both the listener and sender.
pub const DEFAULT_PORT: u16 = 42069;

/// Represents an application-specific UDP payload and its metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpMessage {
    source: SocketAddr,
    payload: Vec<u8>,
}

impl UdpMessage {
    /// Construct a new [`UdpMessage`] from a source address and payload bytes.
    #[must_use]
    pub fn new(source: SocketAddr, payload: Vec<u8>) -> Self {
        Self { source, payload }
    }

    /// Borrow the source address that originated the UDP datagram.
    #[must_use]
    pub fn source(&self) -> SocketAddr {
        self.source
    }

    /// Borrow the raw payload bytes contained in the datagram.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Convert the payload into a UTF-8 string, replacing invalid sequences with the
    /// Unicode replacement character.
    #[must_use]
    pub fn payload_as_utf8_lossy(&self) -> String {
        String::from_utf8_lossy(&self.payload).into_owned()
    }
}

/// Represents a structured payload that can transport text, structured data, or files.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PayloadEnvelope {
    version: u8,
    payload: PayloadKind,
}

impl PayloadEnvelope {
    /// The version identifier embedded into serialized envelopes.
    pub const CURRENT_VERSION: u8 = 1;

    /// Construct an envelope containing plain UTF-8 text.
    #[must_use]
    pub fn text<T: Into<String>>(text: T) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            payload: PayloadKind::Text(text.into()),
        }
    }

    /// Construct an envelope containing arbitrary JSON data.
    #[must_use]
    pub fn json(value: Value) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            payload: PayloadKind::Json(value),
        }
    }

    /// Construct an envelope containing a binary file payload.
    #[must_use]
    pub fn file(filename: Option<String>, bytes: Vec<u8>) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            payload: PayloadKind::File { filename, bytes },
        }
    }

    /// Borrow the payload variant contained within the envelope.
    #[must_use]
    pub fn payload(&self) -> &PayloadKind {
        &self.payload
    }

    /// Retrieve the encoded version identifier.
    #[must_use]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Serialize the envelope into bytes for transport.
    ///
    /// # Errors
    /// Returns [`MessengerError::Serialization`] if the payload cannot be encoded using
    /// `bincode` (e.g., unsupported type or version mismatch).
    pub fn encode(&self) -> Result<Vec<u8>, MessengerError> {
        bincode::serialize(self).map_err(|err| MessengerError::Serialization(err.to_string()))
    }

    /// Deserialize an envelope from bytes captured on the wire.
    ///
    /// # Errors
    /// Returns [`MessengerError::Serialization`] if the provided bytes are not a valid
    /// `PayloadEnvelope` produced by this library.
    pub fn decode(bytes: &[u8]) -> Result<Self, MessengerError> {
        bincode::deserialize(bytes).map_err(|err| MessengerError::Serialization(err.to_string()))
    }
}

/// The different payload types that may be transmitted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PayloadKind {
    /// UTF-8 text message.
    Text(String),
    /// Arbitrary JSON structure.
    Json(Value),
    /// Binary file contents and optional file name metadata.
    File {
        filename: Option<String>,
        bytes: Vec<u8>,
    },
}

impl fmt::Display for PayloadKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(text) => write!(f, "text: {text}"),
            Self::Json(value) => write!(f, "json: {value}"),
            Self::File { filename, bytes } => {
                let name = filename.as_deref().unwrap_or("<unnamed>");
                write!(f, "file: {name} ({} bytes)", bytes.len())
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum MessengerError {
    #[error("failed to bind UDP socket: {0}")]
    SocketBind(#[source] io::Error),
    #[error("failed to send datagram: {0}")]
    SocketSend(#[source] io::Error),
    #[error("failed to receive datagram: {0}")]
    SocketReceive(#[source] io::Error),
    #[error("invalid socket address '{0}'")]
    InvalidSocketAddress(String),
    #[error("payload serialization error: {0}")]
    Serialization(String),
}

/// Bind a UDP socket for sending and receiving application messages.
///
/// The socket is configured with a short read timeout so listener loops may yield
/// periodically when no datagrams are available.
///
/// # Errors
/// Returns [`MessengerError::SocketBind`] when binding or configuring the socket fails.
pub fn bind_socket<A: ToSocketAddrs>(addr: A) -> Result<UdpSocket, MessengerError> {
    let socket = UdpSocket::bind(addr).map_err(MessengerError::SocketBind)?;
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(MessengerError::SocketBind)?;
    Ok(socket)
}

/// Parse a socket address string into a [`SocketAddr`].
///
/// # Errors
/// Returns [`MessengerError::InvalidSocketAddress`] when the string cannot be parsed or
/// resolved into a socket address.
pub fn parse_socket_address(input: &str) -> Result<SocketAddr, MessengerError> {
    input
        .to_socket_addrs()
        .map_err(|_| MessengerError::InvalidSocketAddress(input.to_owned()))?
        .next()
        .ok_or_else(|| MessengerError::InvalidSocketAddress(input.to_owned()))
}

/// Spawn a background thread that listens for UDP datagrams and forwards them to the
/// provided channel.
///
/// # Must Use
/// The returned handle should be joined or detached to avoid leaking threads. The
/// handle resolves to `Result<(), MessengerError>` to surface socket-level failures
/// (e.g., receive errors) to the caller.
#[must_use]
pub fn spawn_listener(
    socket: UdpSocket,
    sender: SyncSender<UdpMessage>,
) -> JoinHandle<Result<(), MessengerError>> {
    thread::spawn(move || {
        let mut buffer = vec![0_u8; 65_507];
        loop {
            match socket.recv_from(&mut buffer) {
                Ok((len, addr)) => {
                    let payload = buffer[..len].to_vec();
                    if sender.send(UdpMessage::new(addr, payload)).is_err() {
                        return Ok(());
                    }
                    thread::yield_now();
                }
                Err(err)
                    if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::TimedOut =>
                {
                    thread::yield_now();
                }
                Err(err) => {
                    return Err(MessengerError::SocketReceive(err));
                }
            }
        }
    })
}

/// Send an application-specific UDP payload to a destination socket address.
///
/// # Errors
/// Returns [`MessengerError::SocketSend`] if the underlying socket send fails.
pub fn send_message(
    socket: &UdpSocket,
    destination: SocketAddr,
    payload: &[u8],
) -> Result<(), MessengerError> {
    socket
        .send_to(payload, destination)
        .map_err(MessengerError::SocketSend)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn udp_message_new_sets_fields() {
        let payload = b"hello network".to_vec();
        let addr: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        let message = UdpMessage::new(addr, payload.clone());

        assert_eq!(message.payload(), payload);
        assert_eq!(message.source(), addr);
    }

    #[test]
    fn udp_message_payload_as_utf8_lossy_handles_invalid_bytes() {
        let message = UdpMessage::new("127.0.0.1:4000".parse().unwrap(), vec![0xF0, 0x28]);
        assert_eq!(message.payload_as_utf8_lossy(), "\u{FFFD}(");
    }

    #[test]
    fn payload_envelope_round_trips_text() {
        let original = PayloadEnvelope::text("hello world");
        let encoded = original.encode().expect("encode succeeds");
        let decoded = PayloadEnvelope::decode(&encoded).expect("decode succeeds");
        assert_eq!(decoded.payload(), original.payload());
        assert_eq!(decoded.version(), PayloadEnvelope::CURRENT_VERSION);
    }

    #[test]
    fn payload_envelope_round_trips_file() {
        let original = PayloadEnvelope::file(Some("example.bin".into()), vec![1, 2, 3]);
        let encoded = original.encode().expect("encode succeeds");
        let decoded = PayloadEnvelope::decode(&encoded).expect("decode succeeds");
        assert_eq!(decoded.payload(), original.payload());
        match decoded.payload() {
            PayloadKind::File { filename, bytes } => {
                assert_eq!(filename.as_deref(), Some("example.bin"));
                assert_eq!(bytes, &vec![1, 2, 3]);
            }
            other => panic!("unexpected payload kind: {other:?}"),
        }
    }

    #[test]
    fn parse_socket_address_parses_valid_input() {
        let addr = parse_socket_address("127.0.0.1:12345").expect("valid address");
        assert_eq!(addr, "127.0.0.1:12345".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parse_socket_address_rejects_invalid_input() {
        let error = parse_socket_address("invalid").expect_err("invalid address");
        match error {
            MessengerError::InvalidSocketAddress(text) => assert_eq!(text, "invalid"),
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn spawn_listener_processes_datagrams_and_exits_on_send_error() {
        let socket = bind_socket("127.0.0.1:0").expect("bind socket");
        let peer_addr = socket.local_addr().expect("local addr");
        let send_socket = socket.try_clone().expect("clone socket");
        let (tx, rx) = mpsc::sync_channel::<UdpMessage>(0);

        let handle = spawn_listener(socket, tx);
        send_socket
            .send_to(b"hello", peer_addr)
            .expect("send datagram");
        let message = rx
            .recv_timeout(Duration::from_secs(1))
            .expect("message available");
        assert_eq!(message.payload(), b"hello");
        assert_eq!(message.source(), peer_addr);

        drop(rx);
        // Wake the listener so it observes the disconnected channel and exits cleanly.
        let _ = send_socket.send_to(&[], peer_addr);
        handle
            .join()
            .expect("listener thread should not panic")
            .expect("listener should exit cleanly");
    }

    #[test]
    fn send_message_dispatches_datagram_successfully() {
        let receiver = bind_socket("127.0.0.1:0").expect("bind receiver");
        let receiver_addr = receiver.local_addr().expect("local addr");

        let sender = bind_socket("127.0.0.1:0").expect("bind sender");
        send_message(&sender, receiver_addr, b"payload").expect("send succeeds");

        let mut buffer = [0_u8; 16];
        let (len, source) = receiver.recv_from(&mut buffer).expect("receive");
        assert_eq!(&buffer[..len], b"payload");
        assert_eq!(source, sender.local_addr().expect("sender addr"));
    }

    #[test]
    fn payload_kind_display_formats_variants() {
        let text = PayloadKind::Text("hello".into());
        assert_eq!(text.to_string(), "text: hello");

        let json = PayloadKind::Json(serde_json::json!({"k": "v"}));
        assert_eq!(json.to_string(), "json: {\"k\":\"v\"}");

        let file = PayloadKind::File {
            filename: Some("file.bin".into()),
            bytes: vec![1, 2, 3, 4],
        };
        assert_eq!(file.to_string(), "file: file.bin (4 bytes)");

        let unnamed = PayloadKind::File {
            filename: None,
            bytes: vec![0; 2],
        };
        assert_eq!(unnamed.to_string(), "file: <unnamed> (2 bytes)");
    }

    #[test]
    fn payload_envelope_decode_rejects_invalid_data() {
        let bytes = b"not a valid envelope";
        let error = PayloadEnvelope::decode(bytes).expect_err("decode should fail");
        match error {
            MessengerError::Serialization(_) => {}
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn bind_socket_sets_read_timeout() {
        let socket = bind_socket("127.0.0.1:0").expect("bind socket");
        let timeout = socket
            .read_timeout()
            .expect("read timeout available")
            .expect("read timeout should be set");
        assert_eq!(timeout, Duration::from_millis(200));
    }

    #[test]
    fn spawn_listener_processes_multiple_datagrams_in_order() {
        let socket = bind_socket("127.0.0.1:0").expect("bind socket");
        let peer_addr = socket.local_addr().expect("local addr");
        let send_socket = socket.try_clone().expect("clone socket");
        let (tx, rx) = mpsc::sync_channel::<UdpMessage>(8);

        let handle = spawn_listener(socket, tx);
        for payload in ["one", "two", "three"] {
            send_socket
                .send_to(payload.as_bytes(), peer_addr)
                .expect("send datagram");
        }

        let mut received = Vec::new();
        for _ in 0..3 {
            let msg = rx
                .recv_timeout(Duration::from_secs(1))
                .expect("message available");
            received.push(msg.payload_as_utf8_lossy());
        }
        assert_eq!(received, ["one", "two", "three"]);

        drop(rx);
        let _ = send_socket.send_to(&[], peer_addr);
        handle
            .join()
            .expect("listener thread should not panic")
            .expect("listener should exit cleanly");
    }
}
