# glowing-happiness

This repository contains a proof-of-concept Rust application that exchanges
custom Ethernet frames between two machines. One instance performs "work" in a
loop (simple counting) and immediately reacts when another peer sends an
application-specific Ethernet frame.

## Prerequisites

Running the examples typically requires administrative privileges or the
`CAP_NET_RAW` capability because the program opens a raw data link socket.

```
sudo setcap cap_net_raw+ep target/debug/ether-demo
```

## building for raspberry pi
 cargo build --release --target=aarch64-unknown-linux-gnu
 
## Usage

Build the project first:

```
cargo build
```

### Run the worker loop
using cargo
```
cargo run --bin ether-demo -- run --interface eth0 --work-delay-ms 500
```
using prebuilt binary
```
sudo ./ether-demo run --interface eth0 --work-delay-ms 500

```
The worker prints periodic work iterations and logs any inbound frames whose
EtherType matches the custom value used by this demo.

### Send a message

using cargo
```
cargo run --bin ether-demo -- send \
  --interface eth0 \
  --destination aa:bb:cc:dd:ee:ff \
  --message "Hello from Sender"
```
using prebuilt binary
```
sudo ./ether-demo send --interface eth0 --destination aa:bb:cc:dd:ee:ff --message "hello from Sender"
```
The sender crafts a single Ethernet frame with the configured payload and
transmits it via the specified interface. The worker reacts to the inbound
frame before resuming its counting loop.
