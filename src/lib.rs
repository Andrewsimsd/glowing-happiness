#![warn(clippy::pedantic)]

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
    pub fn encode(&self) -> Result<Vec<u8>, MessengerError> {
        bincode::serialize(self).map_err(|err| MessengerError::Serialization(err.to_string()))
    }

    /// Deserialize an envelope from bytes captured on the wire.
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
pub fn bind_socket<A: ToSocketAddrs>(addr: A) -> Result<UdpSocket, MessengerError> {
    let socket = UdpSocket::bind(addr).map_err(MessengerError::SocketBind)?;
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(MessengerError::SocketBind)?;
    Ok(socket)
}

/// Parse a socket address string into a [`SocketAddr`].
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
/// The returned handle should be joined or detached to avoid leaking threads.
#[must_use]
pub fn spawn_listener(socket: UdpSocket, sender: SyncSender<UdpMessage>) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut buffer = vec![0_u8; 65_507];
        loop {
            match socket.recv_from(&mut buffer) {
                Ok((len, addr)) => {
                    let payload = buffer[..len].to_vec();
                    if sender.send(UdpMessage::new(addr, payload)).is_err() {
                        break;
                    }
                    thread::yield_now();
                }
                Err(err)
                    if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::TimedOut =>
                {
                    thread::yield_now();
                }
                Err(err) => {
                    eprintln!("listener error: {err}");
                    break;
                }
            }
        }
    })
}

/// Send an application-specific UDP payload to a destination socket address.
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
        handle.join().expect("listener should exit cleanly");
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
}
