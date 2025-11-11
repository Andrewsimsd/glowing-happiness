# Glowing Happiness

## Project Overview

Glowing Happiness is a proof-of-concept Rust application that demonstrates how to exchange custom Ethernet frames directly between peers. One instance of the program performs an iterative "work" loop, while another instance can send application-specific Ethernet frames that interrupt the worker in near real time. The repository showcases how raw sockets can be used to build link-layer messaging workflows without relying on traditional IP networking.

### Key Capabilities

- Opens a raw data-link socket to craft and transmit bespoke Ethernet frames.
- Runs a configurable worker loop that reacts immediately to inbound frames.
- Illustrates how to serialize simple payloads for diagnostics or control messaging on a local network segment.

## Prerequisites

Running the examples typically requires administrative privileges or the `CAP_NET_RAW` capability because the program opens a raw data-link socket. Grant the capability to the built binary after compilation:

```
sudo setcap cap_net_raw+ep target/debug/ether-demo
```

## Building the Project

Compile the binaries before running any examples:

```
cargo build
```

## Running the Examples

### Worker Loop

Launch the worker to observe its periodic progress and inbound frame handling:

```
cargo run --bin ether-demo -- run --interface eth0 --work-delay-ms 500
```

The worker prints its work iterations and logs any inbound frames whose EtherType matches the custom value used by this demo.

### Sending a Custom Frame

Use the `send` subcommand to craft and transmit a single Ethernet frame to a peer on the same broadcast domain:

```
cargo run --bin ether-demo -- send \
  --interface eth0 \
  --destination aa:bb:cc:dd:ee:ff \
  --message "Hello from Rust"
```

The sender emits the frame via the specified interface. The worker reacts to the inbound frame before resuming its counting loop.

## MAC-Layer Messaging vs. IP-Layer Messaging

The example focuses on Layer 2 communication, where frames are addressed by MAC addresses instead of IP addresses. The following considerations can help decide when to use each approach.

### Advantages of MAC-Layer Messaging

- **Lower latency and overhead:** Frames remain on the local link, avoiding IP headers, routing, and network address translation (NAT).
- **Functionality without IP configuration:** Useful for bootstrapping protocols—such as ARP or DHCP—or for specialized control traffic before IP settings are available.
- **Fine-grained hardware control:** Enables custom frame formats for diagnostics, industrial automation, or embedded use cases.

### Drawbacks of MAC-Layer Messaging

- **Limited scope:** Frames do not traverse routers, so communication is confined to a single broadcast domain.
- **Elevated privilege requirements:** Crafting raw frames usually demands administrative rights or `CAP_NET_RAW` capabilities.
- **Hardware-specific behavior:** Differences in link-layer technologies or switch configurations can disrupt communication, and some networks filter multicast or broadcast frames.
- **Security and observability challenges:** Without IP-layer safeguards, spoofing is easier and monitoring tools may provide less visibility.

### Advantages of IP-Layer Messaging

- **Routable at scale:** IP packets can traverse routers, VPNs, and the public Internet, enabling communication beyond the local segment.
- **Rich protocol ecosystem:** Higher-level protocols such as TCP provide reliability, congestion control, and service discovery options.
- **Security and management tooling:** Firewalls, intrusion detection systems, and quality-of-service policies are mature and widely supported.
- **Hardware abstraction:** Standard socket APIs allow applications to operate without worrying about link-layer differences.

### Drawbacks of IP-Layer Messaging

- **Higher overhead:** Additional headers and routing logic increase latency and CPU usage compared to raw Ethernet frames on a quiet LAN.
- **Configuration dependencies:** Proper addressing, subnetting, or DHCP configuration is required for connectivity.
- **Middlebox interference:** NAT devices, firewalls, or traffic shapers may block, rewrite, or throttle packets.
- **Fragmentation and MTU limitations:** Oversized packets can be fragmented or dropped, necessitating additional handling.

### Choosing the Appropriate Layer

Use MAC-layer messaging for specialized, local-link tasks such as device discovery, diagnostics, or bespoke control protocols where minimal overhead and immediacy are critical. Favor IP-layer messaging for applications that need to cross network boundaries, leverage standardized transport protocols, or benefit from existing security and management infrastructure.
