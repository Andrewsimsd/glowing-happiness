# Glowing Happiness

## Project Overview

Glowing Happiness is a proof-of-concept Rust application that demonstrates how to exchange custom UDP datagrams directly between peers. One instance of the program performs an iterative "work" loop, while another instance can send application-specific payloads that interrupt the worker in near real time. The repository showcases how lightweight, connectionless transport can be used for simple control messages without relying on raw link-layer access.

### Key Capabilities

- Binds a UDP socket to craft and transmit bespoke application payloads.
- Runs a configurable worker loop that reacts immediately to inbound datagrams.
- Illustrates how to serialize simple payloads for diagnostics or control messaging on a local network or across routed segments.

## Prerequisites

No special capabilities are required because the program uses standard UDP sockets.

## Building the Project

Compile the binaries before running any examples:

building for local machine
```
cargo build --release
```
building for pi
```
cargo build --release --target=aarch64-unknown-linux-gnu
```
## Running the Examples

### Worker Loop

Launch the worker to observe its periodic progress and inbound datagram handling:

```
cargo run --bin ether-demo -- run --bind 0.0.0.0:42069 --work-delay-ms 500
```
using prebuilt binary
```
./ether-demo run --bind 0.0.0.0:42069 --work-delay-ms 500
```

The worker prints its work iterations and logs any inbound datagrams containing the serialized payload envelope used by this demo.

### Sending a Custom Frame

Use the `send` subcommand to craft and transmit a single UDP datagram to a peer. Payloads can be plain text, JSON structures, or arbitrary files:

using cargo
```
# simple text payload
cargo run --bin ether-demo -- send \
  --bind 0.0.0.0:0 \
  --destination 192.168.1.100:42069 \
  --message "Hello from Sender"

# JSON document describing a complex struct
cargo run --bin ether-demo -- send \
  --destination 192.168.1.100:42069 \
  --json '{"command":"pause","metadata":{"priority":2}}'

# binary file transfer (metadata name inferred from the path)
cargo run --bin ether-demo -- send \
  --destination 192.168.1.100:42069 \
  --file ./diagnostics.tar.gz
```
using prebuilt binary
```
./ether-demo send --destination 192.168.1.100:42069 --message "hello from Sender"
```

Each payload is wrapped inside a serialized envelope that records whether the message is text, JSON, or file data. When sending files you may also provide `--file-name` to override the inferred metadata name. The worker logs the decoded envelope metadata when a datagram arrives, providing visibility into complex structs and file transfers before resuming its counting loop.
Because UDP traffic is routable, you can now reach peers beyond the local broadcast domain so long as intermediate firewalls permit the traffic. Keep in mind that UDP delivery is not guaranteed; choose ports and addresses appropriate for your network environment.
