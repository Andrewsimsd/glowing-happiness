#![warn(clippy::pedantic)]
//! # ether-demo CLI
//!
//! ## Purpose
//! A reference command-line interface for the `glowing_happiness` UDP library. It can run
//! a worker loop that listens for inbound datagrams or send a single structured payload
//! (text, JSON, or file) to a peer.
//!
//! ## Commands
//! - `run`: binds a UDP socket and drains messages while simulating periodic work.
//! - `send`: crafts and dispatches one payload to a destination address.
//!
//! ## Payload Selection
//! The payload flags are mutually exclusive and enforced by clap; exactly one of
//! `--message`, `--json`, or `--file` must be provided. When sending files, metadata is
//! inferred from the path unless `--file-name` is set.
//!
//! ## Error Handling
//! Failures bubble up as `AppError`, wrapping library-level `MessengerError` for transport
//! errors and serde/IO errors for local parsing and file access. Listener thread failures
//! are surfaced at join time so the worker can exit loudly.
//!
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use glowing_happiness::{
    MessengerError, PayloadEnvelope, UdpMessage, bind_socket, parse_socket_address, send_message,
    spawn_listener, DEFAULT_PORT,
};
use serde_json::Value;
use thiserror::Error;

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
        #[arg(long, default_value_t = default_worker_bind())]
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
        #[command(flatten)]
        payload: PayloadArgs,
    },
}

#[derive(Args, Debug)]
#[group(id = "payload", required = true, multiple = false)]
struct PayloadArgs {
    /// Plain-text message payload to send.
    #[arg(long, group = "payload")]
    message: Option<String>,
    /// JSON document describing complex structured data to send.
    #[arg(long, group = "payload")]
    json: Option<String>,
    /// Path to a file whose bytes should be transmitted.
    #[arg(long, group = "payload", value_name = "PATH")]
    file: Option<PathBuf>,
    /// Optional file name metadata to attach when using --file.
    #[arg(long, requires = "file")]
    file_name: Option<String>,
}

fn default_worker_bind() -> String {
    format!("0.0.0.0:{DEFAULT_PORT}")
}

fn main() -> Result<(), AppError> {
    let cli = Cli::parse();

    match cli.command {
        Command::Run {
            bind,
            work_delay_ms,
        } => run_worker(&bind, Duration::from_millis(work_delay_ms)),
        Command::Send {
            bind,
            destination,
            payload,
        } => {
            let envelope = build_payload_envelope(payload)?;
            send_once(&bind, &destination, &envelope)
        }
    }
}

fn run_worker(bind_addr: &str, work_delay: Duration) -> Result<(), AppError> {
    let socket = bind_socket(bind_addr)?;
    let local_addr = socket.local_addr()?;
    let (tx, rx) = mpsc::sync_channel::<UdpMessage>(128);
    let listener = spawn_listener(socket, tx);

    println!("Running work loop bound to {local_addr} with {work_delay:?} delay per iteration");
    println!("Waiting for UDP datagrams on {local_addr}");

    let mut counter: u64 = 0;
    loop {
        counter = counter.wrapping_add(1);
        println!("Work iteration {counter}: performing simulated work");
        thread::sleep(work_delay);

        let mut processed = 0_usize;
        let drain_result = loop {
            match rx.try_recv() {
                Ok(message) => {
                    processed += 1;
                    handle_message(&message);
                }
                Err(err) => break err,
            }
        };

        match drain_result {
            TryRecvError::Empty => {
                if processed > 0 {
                    println!("Processed {processed} message(s) from buffer");
                } else {
                    println!("No buffered messages this cycle");
                }
            }
            TryRecvError::Disconnected => {
                println!("Listener disconnected; exiting work loop");
                break;
            }
        }
    }

    drop(rx);
    match listener.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(AppError::ListenerExited(err)),
        Err(_) => Err(AppError::ListenerPanicked),
    }
}

fn handle_message(message: &UdpMessage) {
    match PayloadEnvelope::decode(message.payload()) {
        Ok(envelope) => {
            println!(
                "Received payload (v{}) from {} with {} bytes: {}",
                envelope.version(),
                message.source(),
                message.payload().len(),
                envelope.payload(),
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
    payload: &PayloadEnvelope,
) -> Result<(), AppError> {
    let socket = bind_socket(bind_addr)?;
    let destination_addr = parse_socket_address(destination)?;
    let payload_bytes = payload.encode()?;

    send_message(&socket, destination_addr, &payload_bytes)?;
    println!(
        "Sent payload from '{}' to {destination_addr} using {} bytes: {}",
        socket.local_addr()?,
        payload_bytes.len(),
        payload.payload(),
    );

    Ok(())
}

fn build_payload_envelope(payload: PayloadArgs) -> Result<PayloadEnvelope, AppError> {
    let PayloadArgs {
        message,
        json,
        file,
        file_name,
    } = payload;

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

    Err(AppError::MissingPayload)
}

#[derive(Debug, Error)]
enum AppError {
    #[error(transparent)]
    Messenger(#[from] MessengerError),
    #[error("listener thread panicked")]
    ListenerPanicked,
    #[error("listener exited with error: {0}")]
    ListenerExited(#[source] MessengerError),
    #[error("invalid JSON payload: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("one of --message, --json, or --file is required")]
    MissingPayload,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;
    use glowing_happiness::PayloadKind;

    #[test]
    fn default_worker_bind_uses_default_port() {
        let bind = default_worker_bind();
        assert!(bind.ends_with(&DEFAULT_PORT.to_string()));
        assert!(bind.starts_with("0.0.0.0:"));
    }

    #[test]
    fn build_payload_envelope_creates_text_variant() {
        let payload = build_payload_envelope(PayloadArgs {
            message: Some("hi".into()),
            json: None,
            file: None,
            file_name: None,
        })
        .expect("payload should build");

        match payload.payload() {
            PayloadKind::Text(text) => assert_eq!(text, "hi"),
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn build_payload_envelope_creates_json_variant() {
        let payload = build_payload_envelope(PayloadArgs {
            message: None,
            json: Some(r#"{"a":1}"#.into()),
            file: None,
            file_name: None,
        })
        .expect("payload should build");

        match payload.payload() {
            PayloadKind::Json(value) => {
                assert_eq!(value, &serde_json::json!({"a": 1}));
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn build_payload_envelope_infers_file_name_when_missing() {
        let dir = tempdir().expect("create tempdir");
        let path = dir.path().join("example.bin");
        let mut file = File::create(&path).expect("create file");
        file.write_all(b"abc").expect("write file");

        let payload = build_payload_envelope(PayloadArgs {
            message: None,
            json: None,
            file: Some(path.clone()),
            file_name: None,
        })
        .expect("payload should build");

        match payload.payload() {
            PayloadKind::File { filename, bytes } => {
                assert_eq!(filename.as_deref(), Some("example.bin"));
                assert_eq!(bytes, b"abc");
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn build_payload_envelope_respects_override_file_name() {
        let dir = tempdir().expect("create tempdir");
        let path = dir.path().join("ignored.bin");
        let mut file = File::create(&path).expect("create file");
        file.write_all(b"xyz").expect("write file");

        let payload = build_payload_envelope(PayloadArgs {
            message: None,
            json: None,
            file: Some(path),
            file_name: Some("override.bin".into()),
        })
        .expect("payload should build");

        match payload.payload() {
            PayloadKind::File { filename, bytes } => {
                assert_eq!(filename.as_deref(), Some("override.bin"));
                assert_eq!(bytes, b"xyz");
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn build_payload_envelope_missing_payload_is_error() {
        let err = build_payload_envelope(PayloadArgs {
            message: None,
            json: None,
            file: None,
            file_name: None,
        })
        .expect_err("missing payload should error");

        match err {
            AppError::MissingPayload => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
