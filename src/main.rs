#![warn(clippy::pedantic)]

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

use clap::{Parser, Subcommand};
use glowing_happiness::{
    EthernetMessage, PayloadEnvelope, PayloadKind, interface_by_name, open_channel,
    parse_mac_address, send_message, spawn_listener,
};
use serde_json::Value;

#[derive(Parser, Debug)]
#[command(name = "ether-demo", author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the worker loop that performs work and reacts to Ethernet messages.
    Run {
        /// The network interface to bind to (e.g. "eth0").
        #[arg(long)]
        interface: String,
        /// Delay between work iterations in milliseconds.
        #[arg(long, default_value_t = 500)]
        work_delay_ms: u64,
    },
    /// Send a single Ethernet frame to a peer.
    Send {
        /// The network interface to send from (e.g. "eth0").
        #[arg(long)]
        interface: String,
        /// Destination MAC address (e.g. "aa:bb:cc:dd:ee:ff").
        #[arg(long)]
        destination: String,
        /// Plain-text message payload to send.
        #[arg(long, conflicts_with_all = ["json", "file"])]
        message: Option<String>,
        /// JSON document describing complex structured data to send.
        #[arg(long, conflicts_with_all = ["message", "file"])]
        json: Option<String>,
        /// Path to a file whose bytes should be transmitted.
        #[arg(long, conflicts_with_all = ["message", "json"], value_name = "PATH")]
        file: Option<PathBuf>,
        /// Optional file name metadata to attach when using --file.
        #[arg(long, requires = "file")]
        file_name: Option<String>,
    },
}

/// Parses the command-line arguments and dispatches to the requested command.
///
/// This function serves as the entry point for the application. It delegates the
/// heavy lifting to either [`run_worker`] or [`send_once`] depending on the
/// selected subcommand.
fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Run {
            interface,
            work_delay_ms,
        } => run_worker(&interface, Duration::from_millis(work_delay_ms)),
        Command::Send {
            interface,
            destination,
            message,
            json,
            file,
            file_name,
        } => {
            let envelope = build_payload_envelope(message, json, file, file_name)?;
            send_once(&interface, &destination, envelope)
        }
    }
}

/// Executes the worker loop that performs background work and listens for frames.
///
/// The worker registers a listener for the application's Ethernet frame type and
/// periodically performs a unit of work when no frames are received. The
/// [`Duration`] controls how long the worker waits before executing another work
/// iteration.
///
/// # Arguments
///
/// * `interface_name` - The name of the network interface to bind to (for example `"eth0"`).
/// * `work_delay` - The delay between work iterations when no frames are received.
///
/// # Errors
///
/// Returns an error if the interface cannot be located, the channel cannot be
/// opened, or any of the underlying I/O operations fail.
fn run_worker(interface_name: &str, work_delay: Duration) -> Result<(), Box<dyn Error>> {
    let interface = interface_by_name(interface_name)?;
    let (_sender, receiver) = open_channel(&interface)?;

    let (tx, rx) = mpsc::sync_channel::<EthernetMessage>(0);
    let listener = spawn_listener(receiver, tx);

    println!(
        "Running work loop on interface '{interface_name}' with {work_delay:?} delay per iteration"
    );
    println!(
        "Waiting for Ethernet frames with type 0x{:04x}",
        glowing_happiness::APPLICATION_ETHER_TYPE.0
    );

    let mut counter: u64 = 0;
    loop {
        match rx.recv_timeout(work_delay) {
            Ok(message) => handle_message(&message),
            Err(RecvTimeoutError::Timeout) => {
                counter = counter.wrapping_add(1);
                println!("Work iteration {counter}");
            }
            Err(RecvTimeoutError::Disconnected) => {
                println!("Listener disconnected; exiting work loop");
                break;
            }
        }
    }

    drop(rx);
    if let Err(err) = listener.join() {
        let message = if let Some(msg) = err.downcast_ref::<&str>() {
            (*msg).to_string()
        } else if let Some(msg) = err.downcast_ref::<String>() {
            msg.clone()
        } else {
            "listener thread panicked".to_string()
        };
        return Err(Box::new(ListenerJoinError { message }));
    }

    Ok(())
}

/// Logs the contents of an incoming application-specific Ethernet frame.
///
/// The function renders the payload as UTF-8 (replacing invalid sequences) and
/// prints the source, payload length, and textual representation to stdout. It is
/// intended to be used as the callback from the worker loop.
fn handle_message(message: &EthernetMessage) {
    match PayloadEnvelope::decode(message.payload()) {
        Ok(envelope) => {
            let (label, details) = payload_description(envelope.payload());
            println!(
                "Received {label} payload (v{}) from {} with {} bytes: {details}",
                envelope.version(),
                message.source(),
                message.payload().len()
            );
        }
        Err(err) => {
            println!(
                "Received raw frame from {} but failed to decode payload ({} bytes): {err}",
                message.source(),
                message.payload().len()
            );
        }
    }
}

/// Sends a single Ethernet frame containing the provided message payload.
///
/// The command resolves the source interface, parses the destination MAC
/// address, and transmits the payload using the application's `EtherType`.
///
/// # Arguments
///
/// * `interface_name` - The interface used for transmitting the frame.
/// * `destination` - The destination MAC address in standard hex notation.
/// * `message` - The UTF-8 payload that should be sent to the destination.
///
/// # Errors
///
/// Returns an error if the interface cannot be opened, the MAC address is
/// malformed, or the frame transmission fails.
fn send_once(
    interface_name: &str,
    destination: &str,
    payload: PayloadEnvelope,
) -> Result<(), Box<dyn Error>> {
    let interface = interface_by_name(interface_name)?;
    let (mut sender, _receiver) = open_channel(&interface)?;
    let destination_mac = parse_mac_address(destination)?;
    let payload_bytes = payload.encode()?;

    send_message(&interface, sender.as_mut(), destination_mac, &payload_bytes)?;
    let (label, details) = payload_description(payload.payload());
    println!(
        "Sent {label} payload ({details}) from '{interface_name}' to {destination_mac} using {} bytes",
        payload_bytes.len()
    );

    Ok(())
}

fn build_payload_envelope(
    message: Option<String>,
    json: Option<String>,
    file: Option<PathBuf>,
    file_name: Option<String>,
) -> Result<PayloadEnvelope, Box<dyn Error>> {
    if let Some(text) = message {
        return Ok(PayloadEnvelope::text(text));
    }

    if let Some(json_text) = json {
        let value: Value = serde_json::from_str(&json_text)?;
        return Ok(PayloadEnvelope::json(value));
    }

    if let Some(path) = file {
        let data = fs::read(&path)?;
        let name = file_name.or_else(|| {
            path.file_name()
                .map(|value| value.to_string_lossy().into_owned())
        });
        return Ok(PayloadEnvelope::file(name, data));
    }

    Err("one of --message, --json, or --file must be provided".into())
}

fn payload_description(payload: &PayloadKind) -> (&'static str, String) {
    match payload {
        PayloadKind::Text(text) => ("text", text.clone()),
        PayloadKind::Json(value) => ("json", value.to_string()),
        PayloadKind::File { filename, bytes } => {
            let name = filename.as_deref().unwrap_or("<unnamed>");
            ("file", format!("{name} ({} bytes)", bytes.len()))
        }
    }
}

#[derive(Debug)]
struct ListenerJoinError {
    message: String,
}

impl fmt::Display for ListenerJoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "listener thread panicked: {}", self.message)
    }
}

impl Error for ListenerJoinError {}
