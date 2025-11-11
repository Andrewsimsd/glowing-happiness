#![warn(clippy::pedantic)]

use std::io::{self, ErrorKind};
use std::str::FromStr;
use std::sync::mpsc::SyncSender;
use std::sync::{Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use pnet::datalink::{
    self, Channel, ChannelType, Config, DataLinkReceiver, DataLinkSender, NetworkInterface,
};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherType, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;
use thiserror::Error;

/// The value 0x88B5 is one of a small block of EtherTypes that the IEEE set aside as “Local Experimental” identifiers.
/// They are intended for in-development or private protocols so that engineers can test new frame formats on real networks
/// without colliding with globally standardized EtherTypes. Because the number sits in that experimental range, it’s safe
/// for an application to use internally while still remaining distinct from production protocols.
pub const APPLICATION_ETHER_TYPE: EtherType = EtherType(0x88B5);

/// Convenience alias for the sender and receiver pair returned by [`open_channel`].
pub type DataLinkChannel = (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>);

type InterfaceProvider = Box<dyn Fn() -> Vec<NetworkInterface> + Send + Sync>;
type ChannelProvider =
    Box<dyn Fn(&NetworkInterface, Config) -> Result<DataLinkChannel, MessengerError> + Send + Sync>;
type BufferAllocator = Box<dyn Fn(usize) -> Vec<u8> + Send + Sync>;

/// # Summary
/// Access the shared provider used to enumerate network interfaces.
///
/// # Returns
/// A mutex guarding the injectable interface provider factory.
fn interface_provider() -> &'static Mutex<InterfaceProvider> {
    static PROVIDER: OnceLock<Mutex<InterfaceProvider>> = OnceLock::new();
    PROVIDER.get_or_init(|| Mutex::new(Box::new(default_interface_provider)))
}

/// # Summary
/// Obtain the shared provider responsible for creating data link channels.
///
/// # Returns
/// A mutex protecting the configurable channel provider callback.
fn channel_provider() -> &'static Mutex<ChannelProvider> {
    static PROVIDER: OnceLock<Mutex<ChannelProvider>> = OnceLock::new();
    PROVIDER.get_or_init(|| Mutex::new(Box::new(default_channel_provider)))
}

/// # Summary
/// Access the shared allocator used to provision packet buffers.
///
/// # Returns
/// A mutex wrapping the allocator callback so tests may override it.
fn buffer_allocator() -> &'static Mutex<BufferAllocator> {
    static ALLOCATOR: OnceLock<Mutex<BufferAllocator>> = OnceLock::new();
    ALLOCATOR.get_or_init(|| Mutex::new(Box::new(default_buffer_allocator)))
}

/// # Summary
/// Retrieve network interfaces using the platform default implementation.
///
/// # Returns
/// A vector containing the interfaces reported by `pnet`.
fn default_interface_provider() -> Vec<NetworkInterface> {
    datalink::interfaces()
}

/// # Summary
/// Open a data link channel using the underlying `pnet` backend.
///
/// # Parameters
/// * `interface` - The interface for which the channel should be opened.
/// * `config` - The configuration describing how to configure the channel.
///
/// # Returns
/// The sender and receiver pair when an Ethernet channel is available.
///
/// # Errors
/// Returns [`MessengerError::UnsupportedChannel`] when the backend does not
/// provide an Ethernet channel for the interface.
fn default_channel_provider(
    interface: &NetworkInterface,
    config: Config,
) -> Result<DataLinkChannel, MessengerError> {
    match datalink::channel(interface, config).map_err(MessengerError::ChannelOpen)? {
        Channel::Ethernet(sender, receiver) => Ok((sender, receiver)),
        #[allow(clippy::wildcard_enum_match_arm)]
        other => {
            drop(other);
            Err(MessengerError::UnsupportedChannel)
        }
    }
}

/// # Summary
/// Allocate a zeroed buffer sized for an Ethernet header and payload.
///
/// # Parameters
/// * `payload_length` - The number of payload bytes that need to fit in the packet.
///
/// # Returns
/// A vector large enough to hold a mutable Ethernet packet for the payload.
fn default_buffer_allocator(payload_length: usize) -> Vec<u8> {
    vec![0_u8; MutableEthernetPacket::minimum_packet_size().saturating_add(payload_length)]
}

/// # Summary
/// Collect the network interfaces from the currently configured provider.
///
/// # Returns
/// A vector of interfaces, allowing tests to supply custom data.
fn interfaces() -> Vec<NetworkInterface> {
    (interface_provider()
        .lock()
        .expect("interface provider poisoned"))()
}

/// # Summary
/// Open a data link channel using the configurable provider abstraction.
///
/// # Parameters
/// * `interface` - The interface for which the channel is desired.
/// * `config` - The configuration applied when opening the channel.
///
/// # Returns
/// The channel pair returned by the provider.
fn open_channel_via_provider(
    interface: &NetworkInterface,
    config: Config,
) -> Result<DataLinkChannel, MessengerError> {
    (channel_provider()
        .lock()
        .expect("channel provider poisoned"))(interface, config)
}

/// # Summary
/// Allocate a packet buffer using the currently active allocator.
///
/// # Parameters
/// * `payload_length` - The number of payload bytes needed for the packet.
///
/// # Returns
/// A vector sized according to the allocator strategy.
fn allocate_buffer(payload_length: usize) -> Vec<u8> {
    (buffer_allocator()
        .lock()
        .expect("buffer allocator poisoned"))(payload_length)
}

/// Represents an application-specific Ethernet frame payload and its metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetMessage {
    source: MacAddr,
    payload: Vec<u8>,
}

impl EthernetMessage {
    /// # Summary
    /// Construct a new [`EthernetMessage`] from a source MAC address and payload bytes.
    ///
    /// # Parameters
    /// * `source` - The MAC address that originated the Ethernet frame.
    /// * `payload` - The raw payload bytes extracted from the Ethernet frame.
    ///
    /// # Returns
    /// Returns a value encapsulating the payload and source metadata so that callers
    /// can process and inspect the received frame contents.
    ///
    /// # Examples
    /// ```
    /// use pnet::util::MacAddr;
    /// use glowing_happiness::EthernetMessage;
    ///
    /// let message = EthernetMessage::new(MacAddr::new(0, 1, 2, 3, 4, 5), b"hello".to_vec());
    /// assert_eq!(message.source(), MacAddr::new(0, 1, 2, 3, 4, 5));
    /// assert_eq!(message.payload(), b"hello");
    /// ```
    #[must_use]
    pub fn new(source: MacAddr, payload: Vec<u8>) -> Self {
        Self { source, payload }
    }

    /// # Summary
    /// Retrieve the MAC address that originated the Ethernet frame.
    ///
    /// # Returns
    /// The source [`MacAddr`] associated with the message.
    ///
    /// # Examples
    /// ```
    /// use pnet::util::MacAddr;
    /// use glowing_happiness::EthernetMessage;
    ///
    /// let message = EthernetMessage::new(MacAddr::new(6, 5, 4, 3, 2, 1), vec![]);
    /// assert_eq!(message.source(), MacAddr::new(6, 5, 4, 3, 2, 1));
    /// ```
    #[must_use]
    pub fn source(&self) -> MacAddr {
        self.source
    }

    /// # Summary
    /// Borrow the raw payload bytes contained in the Ethernet frame.
    ///
    /// # Returns
    /// A slice view over the payload bytes.
    ///
    /// # Examples
    /// ```
    /// use pnet::util::MacAddr;
    /// use glowing_happiness::EthernetMessage;
    ///
    /// let message = EthernetMessage::new(MacAddr::zero(), b"data".to_vec());
    /// assert_eq!(message.payload(), b"data");
    /// ```
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// # Summary
    /// Convert the payload into a UTF-8 string, replacing invalid sequences with the
    /// Unicode replacement character.
    ///
    /// # Returns
    /// A newly allocated [`String`] that lossily represents the payload data.
    ///
    /// # Examples
    /// ```
    /// use pnet::util::MacAddr;
    /// use glowing_happiness::EthernetMessage;
    ///
    /// let message = EthernetMessage::new(MacAddr::zero(), vec![0xF0, 0x28]);
    /// assert_eq!(message.payload_as_utf8_lossy(), "\u{FFFD}(");
    /// ```
    #[must_use]
    pub fn payload_as_utf8_lossy(&self) -> String {
        String::from_utf8_lossy(&self.payload).into_owned()
    }
}

#[derive(Debug, Error)]
pub enum MessengerError {
    #[error("interface '{0}' not found")]
    InterfaceNotFound(String),
    #[error("interface '{0}' does not have a MAC address")]
    MissingMacAddress(String),
    #[error("failed to open data link channel: {0}")]
    ChannelOpen(#[source] io::Error),
    #[error("sending packets is not supported on this channel")]
    SendNotSupported,
    #[error("failed to send packet: {0}")]
    SendFailure(#[source] io::Error),
    #[error("failed to allocate packet buffer")]
    PacketAllocation,
    #[error("invalid MAC address '{0}'")]
    InvalidMacAddress(String),
    #[error("unsupported data link channel type")]
    UnsupportedChannel,
}

/// # Summary
/// Locate a network interface on the host by matching its system-provided name.
///
/// # Parameters
/// * `name` - The interface name, such as `"eth0"` or `"en0"`.
///
/// # Returns
/// On success, returns the [`NetworkInterface`] matching the supplied name.
///
/// # Errors
/// Returns [`MessengerError::InterfaceNotFound`] when the interface cannot be located
/// by the provider.
///
/// # Examples
/// ```no_run
/// # use glowing_happiness::interface_by_name;
/// let interface = interface_by_name("eth0")?;
/// println!("Using interface: {}", interface.name);
/// # Ok::<(), glowing_happiness::MessengerError>(())
/// ```
pub fn interface_by_name(name: &str) -> Result<NetworkInterface, MessengerError> {
    interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
        .ok_or_else(|| MessengerError::InterfaceNotFound(name.to_owned()))
}

/// # Summary
/// Create a data link sender/receiver pair bound to the specified interface and
/// configured for application-level Ethernet frames.
///
/// # Parameters
/// * `interface` - The network interface that should be used for the channel.
///
/// # Returns
/// A tuple containing the data link sender and receiver.
///
/// # Errors
/// Returns [`MessengerError::ChannelOpen`] when the underlying backend fails to
/// create the channel or [`MessengerError::UnsupportedChannel`] when Ethernet
/// transport is not available.
///
/// # Examples
/// ```no_run
/// # use glowing_happiness::{interface_by_name, open_channel};
/// let interface = interface_by_name("eth0")?;
/// let (mut sender, mut receiver) = open_channel(&interface)?;
/// # Ok::<(), glowing_happiness::MessengerError>(())
/// ```
pub fn open_channel(interface: &NetworkInterface) -> Result<DataLinkChannel, MessengerError> {
    let config = Config {
        read_timeout: Some(Duration::from_millis(200)),
        channel_type: ChannelType::Layer2,
        ..Config::default()
    };

    open_channel_via_provider(interface, config)
}

/// # Summary
/// Parse a MAC address string using standard hexadecimal formatting rules.
///
/// # Parameters
/// * `input` - Text in colon- or hyphen-delimited hexadecimal notation.
///
/// # Returns
/// The parsed [`MacAddr`] if the input represents a valid MAC address.
///
/// # Errors
/// Returns [`MessengerError::InvalidMacAddress`] when the provided text fails to
/// conform to accepted MAC address formats.
///
/// # Examples
/// ```
/// use glowing_happiness::parse_mac_address;
///
/// let mac = parse_mac_address("00:11:22:33:44:55")?;
/// assert_eq!(mac.to_string(), "00:11:22:33:44:55");
/// # Ok::<(), glowing_happiness::MessengerError>(())
/// ```
pub fn parse_mac_address(input: &str) -> Result<MacAddr, MessengerError> {
    MacAddr::from_str(input).map_err(|_| MessengerError::InvalidMacAddress(input.to_owned()))
}

/// # Summary
/// Spawn a background thread that listens for application Ethernet frames and forwards
/// them to the provided channel.
///
/// # Parameters
/// * `receiver` - The data link receiver delivering raw Ethernet frames.
/// * `sender` - The bounded channel used to forward parsed [`EthernetMessage`] values.
///
/// # Returns
/// A [`JoinHandle`] that may be used to wait for the listener thread to finish.
#[must_use]
pub fn spawn_listener(
    mut receiver: Box<dyn DataLinkReceiver>,
    sender: SyncSender<EthernetMessage>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        loop {
            match receiver.next() {
                Ok(frame) => {
                    if let Some(packet) = EthernetPacket::new(frame)
                        && packet.get_ethertype() == APPLICATION_ETHER_TYPE
                    {
                        let message =
                            EthernetMessage::new(packet.get_source(), packet.payload().to_vec());
                        if sender.send(message).is_err() {
                            break;
                        }
                        thread::yield_now();
                    }
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

/// # Summary
/// Send an application-specific Ethernet frame to a destination MAC address.
///
/// # Parameters
/// * `interface` - The network interface that supplies the source MAC address.
/// * `data_link_sender` - The sender implementation obtained from [`open_channel`].
/// * `destination` - The destination MAC address that should receive the frame.
/// * `payload` - The payload bytes to embed in the application frame.
///
/// # Returns
/// Returns `Ok(())` when the frame is dispatched to the underlying transport.
///
/// # Errors
/// * [`MessengerError::MissingMacAddress`] if the interface lacks a hardware
///   address.
/// * [`MessengerError::PacketAllocation`] when the packet buffer cannot be
///   allocated.
/// * [`MessengerError::SendNotSupported`] if the sender backend refuses to send
///   frames.
/// * [`MessengerError::SendFailure`] when the backend reports an I/O error.
///
/// # Examples
/// ```no_run
/// # use glowing_happiness::{interface_by_name, open_channel, parse_mac_address, send_message};
/// # use pnet::util::MacAddr;
/// let interface = interface_by_name("eth0")?;
/// let (mut sender, mut receiver) = open_channel(&interface)?;
/// let destination = parse_mac_address("AA:BB:CC:DD:EE:FF")?;
/// send_message(&interface, sender.as_mut(), destination, b"hello world")?;
/// # drop(receiver);
/// # Ok::<(), glowing_happiness::MessengerError>(())
/// ```
pub fn send_message(
    interface: &NetworkInterface,
    data_link_sender: &mut dyn DataLinkSender,
    destination: MacAddr,
    payload: &[u8],
) -> Result<(), MessengerError> {
    let source = interface
        .mac
        .ok_or_else(|| MessengerError::MissingMacAddress(interface.name.clone()))?;

    let mut buffer = allocate_buffer(payload.len());
    let mut packet =
        MutableEthernetPacket::new(&mut buffer).ok_or(MessengerError::PacketAllocation)?;
    packet.set_destination(destination);
    packet.set_source(source);
    packet.set_ethertype(APPLICATION_ETHER_TYPE);
    packet.set_payload(payload);

    data_link_sender
        .send_to(packet.packet(), None)
        .ok_or(MessengerError::SendNotSupported)?
        .map_err(MessengerError::SendFailure)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::Duration;

    #[derive(Clone)]
    enum FrameEvent {
        Data(Vec<u8>),
        Error(ErrorKind),
    }

    struct StubReceiver {
        events: Vec<FrameEvent>,
        index: usize,
        buffer: Option<Vec<u8>>,
    }

    impl StubReceiver {
        fn new(events: Vec<FrameEvent>) -> Self {
            Self {
                events,
                index: 0,
                buffer: None,
            }
        }
    }

    impl DataLinkReceiver for StubReceiver {
        fn next(&mut self) -> io::Result<&[u8]> {
            if self.index >= self.events.len() {
                return Err(io::Error::from(ErrorKind::TimedOut));
            }

            let event = &self.events[self.index];
            self.index += 1;
            match event {
                FrameEvent::Data(data) => {
                    self.buffer = Some(data.clone());
                    Ok(self.buffer.as_deref().expect("buffer missing"))
                }
                FrameEvent::Error(kind) => Err(io::Error::from(*kind)),
            }
        }
    }

    #[derive(Clone, Copy)]
    enum SendOutcome {
        Success,
        Error(ErrorKind),
        Unsupported,
    }

    struct TestSender {
        packets: Arc<StdMutex<Vec<Vec<u8>>>>,
        send_outcome: SendOutcome,
    }

    impl TestSender {
        fn new(packets: Arc<StdMutex<Vec<Vec<u8>>>>, send_outcome: SendOutcome) -> Self {
            Self {
                packets,
                send_outcome,
            }
        }
    }

    impl DataLinkSender for TestSender {
        fn build_and_send(
            &mut self,
            num_packets: usize,
            packet_size: usize,
            func: &mut dyn FnMut(&mut [u8]),
        ) -> Option<io::Result<()>> {
            for _ in 0..num_packets {
                let mut packet = vec![0_u8; packet_size];
                func(&mut packet);
                self.packets.lock().unwrap().push(packet);
            }
            Some(Ok(()))
        }

        fn send_to(
            &mut self,
            packet: &[u8],
            _dst: Option<NetworkInterface>,
        ) -> Option<io::Result<()>> {
            self.packets.lock().unwrap().push(packet.to_vec());
            match self.send_outcome {
                SendOutcome::Success => Some(Ok(())),
                SendOutcome::Error(kind) => Some(Err(io::Error::from(kind))),
                SendOutcome::Unsupported => None,
            }
        }
    }

    struct InterfaceProviderGuard {
        previous: Option<InterfaceProvider>,
    }

    impl InterfaceProviderGuard {
        fn set<F>(provider: F) -> Self
        where
            F: Fn() -> Vec<NetworkInterface> + Send + Sync + 'static,
        {
            let mut lock = super::interface_provider().lock().unwrap();
            let previous = mem::replace(&mut *lock, Box::new(provider));
            Self {
                previous: Some(previous),
            }
        }
    }

    impl Drop for InterfaceProviderGuard {
        fn drop(&mut self) {
            if let Some(previous) = self.previous.take() {
                *super::interface_provider().lock().unwrap() = previous;
            }
        }
    }

    struct ChannelProviderGuard {
        previous: Option<ChannelProvider>,
    }

    impl ChannelProviderGuard {
        fn set<F>(provider: F) -> Self
        where
            F: Fn(&NetworkInterface, Config) -> Result<DataLinkChannel, MessengerError>
                + Send
                + Sync
                + 'static,
        {
            let mut lock = super::channel_provider().lock().unwrap();
            let previous = mem::replace(&mut *lock, Box::new(provider));
            Self {
                previous: Some(previous),
            }
        }
    }

    impl Drop for ChannelProviderGuard {
        fn drop(&mut self) {
            if let Some(previous) = self.previous.take() {
                *super::channel_provider().lock().unwrap() = previous;
            }
        }
    }

    struct BufferAllocatorGuard {
        previous: Option<BufferAllocator>,
    }

    impl BufferAllocatorGuard {
        fn set<F>(allocator: F) -> Self
        where
            F: Fn(usize) -> Vec<u8> + Send + Sync + 'static,
        {
            let mut lock = super::buffer_allocator().lock().unwrap();
            let previous = mem::replace(&mut *lock, Box::new(allocator));
            Self {
                previous: Some(previous),
            }
        }
    }

    impl Drop for BufferAllocatorGuard {
        fn drop(&mut self) {
            if let Some(previous) = self.previous.take() {
                *super::buffer_allocator().lock().unwrap() = previous;
            }
        }
    }

    fn test_interface(name: &str, mac: Option<MacAddr>) -> NetworkInterface {
        NetworkInterface {
            name: name.to_owned(),
            description: String::new(),
            index: 1,
            mac,
            ips: Vec::new(),
            flags: 0,
        }
    }

    fn build_frame(source: MacAddr, ethertype: EtherType, payload: &[u8]) -> Vec<u8> {
        let mut buffer =
            vec![0_u8; MutableEthernetPacket::minimum_packet_size().saturating_add(payload.len())];
        let mut packet = MutableEthernetPacket::new(&mut buffer).expect("packet creation");
        packet.set_destination(MacAddr::broadcast());
        packet.set_source(source);
        packet.set_ethertype(ethertype);
        packet.set_payload(payload);
        buffer
    }

    #[test]
    fn ethernet_message_new_sets_fields() {
        let payload = b"hello network".to_vec();
        let mac = MacAddr::new(0, 1, 2, 3, 4, 5);
        let message = EthernetMessage::new(mac, payload.clone());

        assert_eq!(message.payload(), payload);
        assert_eq!(message.source(), mac);
    }

    #[test]
    fn ethernet_message_payload_as_utf8_lossy_handles_invalid_bytes() {
        let message = EthernetMessage::new(MacAddr::zero(), vec![0xF0, 0x28]);
        assert_eq!(message.payload_as_utf8_lossy(), "\u{FFFD}(");
    }

    #[test]
    fn interface_by_name_returns_matching_interface() {
        let interfaces = vec![test_interface("eth0", Some(MacAddr::broadcast()))];
        let shared = Arc::new(interfaces);
        let _guard = InterfaceProviderGuard::set({
            let shared = Arc::clone(&shared);
            move || (*shared).clone()
        });

        let interface = interface_by_name("eth0").expect("interface should exist");
        assert_eq!(interface.name, "eth0");
    }

    #[test]
    fn interface_by_name_reports_missing_interface() {
        let _guard = InterfaceProviderGuard::set(|| Vec::new());
        let error = interface_by_name("does-not-exist").expect_err("missing interface");
        match error {
            MessengerError::InterfaceNotFound(name) => assert_eq!(name, "does-not-exist"),
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn open_channel_returns_provider_value() {
        let interface = test_interface("eth0", Some(MacAddr::broadcast()));
        let _guard = ChannelProviderGuard::set(|_, _| {
            Ok((
                Box::new(TestSender::new(
                    Arc::new(StdMutex::new(Vec::new())),
                    SendOutcome::Success,
                )),
                Box::new(StubReceiver::new(Vec::new())),
            ))
        });

        open_channel(&interface).expect("channel should open");
    }

    #[test]
    fn open_channel_propagates_errors() {
        let interface = test_interface("eth0", Some(MacAddr::broadcast()));
        let _guard = ChannelProviderGuard::set(|_, _| Err(MessengerError::UnsupportedChannel));

        let result = open_channel(&interface);
        assert!(matches!(result, Err(MessengerError::UnsupportedChannel)));

        drop(_guard);

        let guard = ChannelProviderGuard::set(|_, _| {
            Err(MessengerError::ChannelOpen(io::Error::from(
                ErrorKind::Other,
            )))
        });
        let result = open_channel(&interface);
        match result {
            Err(MessengerError::ChannelOpen(_)) => {}
            Err(other) => panic!("unexpected error variant: {other:?}"),
            Ok(_) => panic!("expected channel open error"),
        }
        drop(guard);
    }

    #[test]
    fn parse_mac_address_parses_valid_input() {
        let mac = parse_mac_address("00:11:22:33:44:55").expect("valid mac");
        assert_eq!(mac.to_string(), "00:11:22:33:44:55");
    }

    #[test]
    fn parse_mac_address_rejects_invalid_input() {
        let error = parse_mac_address("invalid").expect_err("invalid mac");
        match error {
            MessengerError::InvalidMacAddress(text) => assert_eq!(text, "invalid"),
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn spawn_listener_processes_matching_frames_and_exits_on_send_error() {
        let frames = vec![
            FrameEvent::Error(ErrorKind::WouldBlock),
            FrameEvent::Error(ErrorKind::TimedOut),
            FrameEvent::Data(build_frame(
                MacAddr::new(0, 1, 2, 3, 4, 5),
                EtherType(0),
                b"ignored",
            )),
            FrameEvent::Data(build_frame(
                MacAddr::new(6, 7, 8, 9, 10, 11),
                APPLICATION_ETHER_TYPE,
                b"hello",
            )),
            FrameEvent::Data(build_frame(
                MacAddr::new(12, 13, 14, 15, 16, 17),
                APPLICATION_ETHER_TYPE,
                b"goodbye",
            )),
        ];
        let receiver: Box<dyn DataLinkReceiver> = Box::new(StubReceiver::new(frames));
        let (tx, rx) = mpsc::sync_channel(0);

        let handle = spawn_listener(receiver, tx);
        let message = rx
            .recv_timeout(Duration::from_secs(1))
            .expect("message available");
        assert_eq!(message.payload(), b"hello");
        assert_eq!(message.source(), MacAddr::new(6, 7, 8, 9, 10, 11));

        drop(rx);
        handle.join().expect("listener should exit cleanly");
    }

    #[test]
    fn send_message_dispatches_frame_successfully() {
        let packets = Arc::new(StdMutex::new(Vec::new()));
        let sender = TestSender::new(Arc::clone(&packets), SendOutcome::Success);
        let mut sender: Box<dyn DataLinkSender> = Box::new(sender);
        let interface = test_interface("eth0", Some(MacAddr::new(0, 1, 2, 3, 4, 5)));
        let destination = MacAddr::new(5, 4, 3, 2, 1, 0);

        send_message(&interface, sender.as_mut(), destination, b"payload").expect("send succeeds");

        let packets = packets.lock().unwrap();
        assert_eq!(packets.len(), 1);
        let packet = EthernetPacket::new(&packets[0]).expect("packet parse");
        assert_eq!(packet.get_destination(), destination);
        assert_eq!(packet.get_source(), interface.mac.expect("mac"));
        assert_eq!(packet.get_ethertype(), APPLICATION_ETHER_TYPE);
        assert_eq!(packet.payload(), b"payload");
    }

    #[test]
    fn send_message_requires_mac_address() {
        let packets = Arc::new(StdMutex::new(Vec::new()));
        let sender = TestSender::new(Arc::clone(&packets), SendOutcome::Success);
        let mut sender: Box<dyn DataLinkSender> = Box::new(sender);
        let interface = test_interface("eth0", None);

        let error = send_message(
            &interface,
            sender.as_mut(),
            MacAddr::broadcast(),
            b"payload",
        )
        .expect_err("mac missing");
        assert!(matches!(error, MessengerError::MissingMacAddress(_)));
        assert!(packets.lock().unwrap().is_empty());
    }

    #[test]
    fn send_message_detects_send_not_supported() {
        let packets = Arc::new(StdMutex::new(Vec::new()));
        let sender = TestSender::new(Arc::clone(&packets), SendOutcome::Unsupported);
        let mut sender: Box<dyn DataLinkSender> = Box::new(sender);
        let interface = test_interface("eth0", Some(MacAddr::zero()));

        let error = send_message(
            &interface,
            sender.as_mut(),
            MacAddr::broadcast(),
            b"payload",
        )
        .expect_err("unsupported");
        assert!(matches!(error, MessengerError::SendNotSupported));
    }

    #[test]
    fn send_message_propagates_send_failures() {
        let packets = Arc::new(StdMutex::new(Vec::new()));
        let sender = TestSender::new(Arc::clone(&packets), SendOutcome::Error(ErrorKind::Other));
        let mut sender: Box<dyn DataLinkSender> = Box::new(sender);
        let interface = test_interface("eth0", Some(MacAddr::zero()));

        let error = send_message(
            &interface,
            sender.as_mut(),
            MacAddr::broadcast(),
            b"payload",
        )
        .expect_err("send failure");
        assert!(matches!(error, MessengerError::SendFailure(_)));
    }

    #[test]
    fn send_message_handles_packet_allocation_failure() {
        let packets = Arc::new(StdMutex::new(Vec::new()));
        let sender = TestSender::new(Arc::clone(&packets), SendOutcome::Success);
        let mut sender: Box<dyn DataLinkSender> = Box::new(sender);
        let interface = test_interface("eth0", Some(MacAddr::zero()));
        let _guard = BufferAllocatorGuard::set(|_| Vec::new());

        let error = send_message(
            &interface,
            sender.as_mut(),
            MacAddr::broadcast(),
            b"payload",
        )
        .expect_err("allocation failure");
        assert!(matches!(error, MessengerError::PacketAllocation));
    }
}
