#![warn(clippy::pedantic)]

use std::io::{self, ErrorKind};
use std::str::FromStr;
use std::sync::mpsc::Sender;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use pnet::datalink::{
    self, Channel, ChannelType, Config, DataLinkReceiver, DataLinkSender, NetworkInterface,
};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherType, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;
use thiserror::Error;

pub const APPLICATION_ETHER_TYPE: EtherType = EtherType(0x88B5);

/// Convenience alias for the sender and receiver pair returned by [`open_channel`].
pub type DataLinkChannel = (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>);

/// Represents an application-specific Ethernet frame payload and its metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetMessage {
    source: MacAddr,
    payload: Vec<u8>,
}

impl EthernetMessage {
    #[must_use]
    pub fn new(source: MacAddr, payload: Vec<u8>) -> Self {
        Self { source, payload }
    }

    #[must_use]
    pub fn source(&self) -> MacAddr {
        self.source
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

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

/// Locate a network interface by name.
///
/// # Errors
/// Returns [`MessengerError::InterfaceNotFound`] when the interface cannot be found.
pub fn interface_by_name(name: &str) -> Result<NetworkInterface, MessengerError> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
        .ok_or_else(|| MessengerError::InterfaceNotFound(name.to_owned()))
}

/// Create a data link sender/receiver pair bound to the specified interface.
///
/// # Errors
/// Returns [`MessengerError::ChannelOpen`] if the channel cannot be created or
/// [`MessengerError::UnsupportedChannel`] when the backend does not expose an
/// Ethernet data link channel.
pub fn open_channel(interface: &NetworkInterface) -> Result<DataLinkChannel, MessengerError> {
    let config = Config {
        read_timeout: Some(Duration::from_millis(200)),
        channel_type: ChannelType::Layer2,
        ..Config::default()
    };

    match datalink::channel(interface, config).map_err(MessengerError::ChannelOpen)? {
        Channel::Ethernet(sender, receiver) => Ok((sender, receiver)),
        #[allow(clippy::wildcard_enum_match_arm)]
        other => {
            drop(other);
            Err(MessengerError::UnsupportedChannel)
        }
    }
}

/// Parse a MAC address string.
///
/// # Errors
/// Returns [`MessengerError::InvalidMacAddress`] when the provided text is not a
/// valid MAC address.
pub fn parse_mac_address(input: &str) -> Result<MacAddr, MessengerError> {
    MacAddr::from_str(input).map_err(|_| MessengerError::InvalidMacAddress(input.to_owned()))
}

#[must_use]
pub fn spawn_listener(
    mut receiver: Box<dyn DataLinkReceiver>,
    sender: Sender<EthernetMessage>,
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
                    }
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {}
                Err(err) if err.kind() == ErrorKind::TimedOut => {}
                Err(err) => {
                    eprintln!("listener error: {err}");
                }
            }
        }
    })
}

/// Send an application Ethernet frame to the provided destination.
///
/// # Errors
/// Returns [`MessengerError::MissingMacAddress`] if the interface lacks a source
/// MAC address, [`MessengerError::PacketAllocation`] when packet allocation
/// fails, [`MessengerError::SendNotSupported`] if the sender backend does not
/// support sending frames, or [`MessengerError::SendFailure`] for lower-level
/// I/O errors.
pub fn send_message(
    interface: &NetworkInterface,
    data_link_sender: &mut Box<dyn DataLinkSender>,
    destination: MacAddr,
    payload: &[u8],
) -> Result<(), MessengerError> {
    let source = interface
        .mac
        .ok_or_else(|| MessengerError::MissingMacAddress(interface.name.clone()))?;

    let mut buffer = vec![0_u8; MutableEthernetPacket::minimum_packet_size() + payload.len()];
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

    #[test]
    fn payload_as_utf8_lossy_round_trip() {
        let payload = b"hello network".to_vec();
        let mac = MacAddr::new(0, 1, 2, 3, 4, 5);
        let message = EthernetMessage::new(mac, payload.clone());

        assert_eq!(message.payload(), payload);
        assert_eq!(message.payload_as_utf8_lossy(), "hello network");
        assert_eq!(message.source(), mac);
    }
}
