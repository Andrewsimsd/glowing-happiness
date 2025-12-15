#![warn(clippy::pedantic)]

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::Duration;

use clap::{Parser, Subcommand};
use glowing_happiness::{
    PayloadEnvelope, PayloadKind, UdpMessage, bind_socket, parse_socket_address, send_message,
    spawn_listener,
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
    /// Run the worker loop that performs work and reacts to UDP messages.
    Run {
        /// The address to bind to (e.g. "0.0.0.0:42069").
        #[arg(long, default_value = "0.0.0.0:42069")]
        bind: String,
        /// Delay between work iterations in milliseconds.
        #[arg(long, default_value_t = 500)]
        work_delay_ms: u64,
    },
    /// Send a single UDP datagram to a peer.
    Send {
        /// The address to bind locally (e.g. "0.0.0.0:0").
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: String,
        /// Destination socket address (e.g. "192.168.1.10:42069").
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

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Run {
            bind,
            work_delay_ms,
        } => run_worker(&bind, Duration::from_millis(work_delay_ms)),
        Command::Send {
            bind,
            destination,
            message,
            json,
            file,
            file_name,
        } => {
            let envelope = build_payload_envelope(message, json, file, file_name)?;
            send_once(&bind, &destination, envelope)
        }
    }
}

fn run_worker(bind_addr: &str, work_delay: Duration) -> Result<(), Box<dyn Error>> {
    let socket = bind_socket(bind_addr)?;
    let local_addr = socket.local_addr()?;
    let (tx, rx) = mpsc::sync_channel::<UdpMessage>(128);
    let listener = spawn_listener(socket, tx);

    println!("Running work loop bound to {local_addr} with {work_delay:?} delay per iteration");
    println!("Waiting for UDP datagrams on {local_addr}");

    let mut counter: u64 = 0;
    'work: loop {
        counter = counter.wrapping_add(1);
        println!("Work iteration {counter}: performing simulated work");
        thread::sleep(work_delay);

        let mut processed = 0;
        loop {
            match rx.try_recv() {
                Ok(message) => {
                    processed += 1;
                    handle_message(&message);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    println!("Listener disconnected; exiting work loop");
                    break 'work;
                }
            }
        }

        if processed > 0 {
            println!("Processed {processed} message(s) from buffer");
        } else {
            println!("No buffered messages this cycle");
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

fn handle_message(message: &UdpMessage) {
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
                "Received raw datagram from {} but failed to decode payload ({} bytes): {err}",
                message.source(),
                message.payload().len()
            );
        }
    }
}

fn send_once(
    bind_addr: &str,
    destination: &str,
    payload: PayloadEnvelope,
) -> Result<(), Box<dyn Error>> {
    let socket = bind_socket(bind_addr)?;
    let destination_addr = parse_socket_address(destination)?;
    let payload_bytes = payload.encode()?;

    send_message(&socket, destination_addr, &payload_bytes)?;
    let (label, details) = payload_description(payload.payload());
    println!(
        "Sent {label} payload ({details}) from '{}' to {destination_addr} using {} bytes",
        socket.local_addr()?,
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
    if let Some(message) = message {
        return Ok(PayloadEnvelope::text(message));
    }

    if let Some(json) = json {
        let value: Value = serde_json::from_str(&json)?;
        return Ok(PayloadEnvelope::json(value));
    }

    if let Some(path) = file {
        let bytes = fs::read(&path)?;
        let name = file_name.or_else(|| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        });
        return Ok(PayloadEnvelope::file(name, bytes));
    }

    Err(Box::new(UserInputError(
        "one of --message, --json, or --file is required".into(),
    )))
}

fn payload_description(payload: &PayloadKind) -> (&'static str, String) {
    match payload {
        PayloadKind::Text(text) => ("text", text.clone()),
        PayloadKind::Json(value) => ("json", value.to_string()),
        PayloadKind::File { filename, bytes } => {
            let name = filename.clone().unwrap_or_else(|| "<unnamed>".into());
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
        write!(f, "{message}", message = self.message)
    }
}

impl Error for ListenerJoinError {}

#[derive(Debug)]
struct UserInputError(String);

impl fmt::Display for UserInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{message}", message = self.0)
    }
}

impl Error for UserInputError {}
