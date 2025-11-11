#![warn(clippy::pedantic)]

use std::error::Error;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

use clap::{Parser, Subcommand};
use glowing_happiness::{
    EthernetMessage, interface_by_name, open_channel, parse_mac_address, send_message,
    spawn_listener,
};

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
        /// Message payload to send.
        #[arg(long)]
        message: String,
    },
}

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
        } => send_once(&interface, &destination, &message),
    }
}

fn run_worker(interface_name: &str, work_delay: Duration) -> Result<(), Box<dyn Error>> {
    let interface = interface_by_name(interface_name)?;
    let (_sender, receiver) = open_channel(&interface)?;

    let (tx, rx) = mpsc::sync_channel::<EthernetMessage>(0);
    let _listener = spawn_listener(receiver, tx);

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

    Ok(())
}

fn handle_message(message: &EthernetMessage) {
    let payload = message.payload_as_utf8_lossy();
    println!(
        "Received Ethernet frame from {} with {} bytes: {}",
        message.source(),
        message.payload().len(),
        payload
    );
}

fn send_once(interface_name: &str, destination: &str, message: &str) -> Result<(), Box<dyn Error>> {
    let interface = interface_by_name(interface_name)?;
    let (mut sender, _receiver) = open_channel(&interface)?;
    let destination_mac = parse_mac_address(destination)?;

    send_message(&interface, &mut sender, destination_mac, message.as_bytes())?;
    println!(
        "Sent {} bytes from '{interface_name}' to {destination_mac}",
        message.len()
    );

    Ok(())
}
