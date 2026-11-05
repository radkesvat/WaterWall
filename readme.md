# WaterWall

![GitHub commit activity](https://img.shields.io/github/commit-activity/m/radkesvat/WaterWall)
[![CI](https://github.com/radkesvat/WaterWall/actions/workflows/ci.yaml/badge.svg)](https://github.com/radkesvat/WaterWall/actions/workflows/ci.yaml)
[![Clang Static Analyzer](https://github.com/radkesvat/WaterWall/actions/workflows/clang_static_analyzer.yml/badge.svg)](https://github.com/radkesvat/WaterWall/actions/workflows/clang_static_analyzer.yml)

**Build network paths by connecting small, configurable nodes.**

WaterWall is a modular runtime for tunneling and proxying, with a core written in C.
It connects listeners, proxies, transports, encryption, routing, and packet processing into
chains defined in JSON. Start with a TCP forward, then compose the pieces needed
for an encrypted tunnel, a proxy service, or an IP packet gateway.

It lets you combine existing protocols and build complex network topologies
without writing low-level networking code.
*(Though admittedly, it might make things feel more complex depending on how you use it.)*

[Read the documentation](https://radkesvat.github.io/WaterWall-Docs/docs/intro) ·
[Download a release](https://github.com/radkesvat/WaterWall/releases) ·
[Support development](https://radkesvat-support.vercel.app/)

## How it works

Each node does one job. A listener accepts traffic, middle nodes process it, and
an outbound adapter sends it to the next machine or service. The `next` field
connects a node to another node by name; replies travel back through the chain.

A TCP forward needs two nodes:

```text
TcpListener -> TcpConnector
```

A Tcp-Mux tunnel between 2 servers is as simple as that:

```text
server 1:

TcpListener -> MuxClient -> TcpConnector [to server 2]

server 2:

TcpListener -> MuxServer -> TcpConnector [to your local service]
```

*(Waterwall’s mux is highly customizable and very capable! It's one of the few mux implementations that can use Linux `splice` or maintain a fixed, non-increasing number of long-lived connections, depending on your needs.)*


A local HTTP proxy adds a node that reads the application's requested destination:

```text
TcpListener -> HttpProxyServer -> TcpConnector
```

or SOCKS5:

```text
TcpUdpListener -> Socks5Server -> TcpUdpConnector
```

Tun to SOCKS5:

```text
TunDevice -> PacketsToConnection -> Socks5Client -> TcpUdpConnector
```

To carry a TCP service over QUIC, use matching chains on two machines:

```text
Client: TcpListener -> QuicClient -> UdpConnector
Server: UdpListener -> QuicServer -> TcpConnector
```

*(Kcp could also be used instead of quic)*

Here, the UDP nodes carry QUIC between the machines, while the server's TCP
connector reaches the actual service. QUIC supplies the reliable encrypted
stream; the application can keep using TCP.

Streams, UDP datagrams, and raw IP packets have different requirements. Choose
compatible nodes and use an explicit bridge when crossing those boundaries.
The [node selection guide](https://radkesvat.github.io/WaterWall-Docs/docs/getting-started/tutorial-part4)
explains the available combinations and their setup.

## What you can build

| Goal | Building blocks |
| --- | --- |
| Forward services or serve proxy clients | TCP/UDP adapters, SOCKS5, HTTP proxy, VLESS, VMess, and Trojan nodes. |
| Protect and carry traffic | TLS, Reality, QUIC, AEAD encryption, HTTP/WebSocket transports, and stream/datagram conversion. |
| Connect packet networks | TUN interfaces, in-chain WireGuard, raw packet I/O, and bridges between IP packets and connection or stream paths. |
| Adapt connection paths | Multiplexing, reverse tunnels, connection racing, separate upload/download paths, and keepalives. |
| Route traffic and manage access | Routing rules, protocol sniffing, shared user authentication, traffic limits, and an administration API. |
| Inspect and test a chain | Payload logging, deterministic integrity tests, throughput tests, and controlled fault injection. |

The [node reference](https://radkesvat.github.io/WaterWall-Docs/docs/noderefs/all-nodes)
covers each node's settings, supported modes, and practical examples. Features
such as encryption, authentication, and framing are configured explicitly; node
order is part of the design.

## Try a local TCP forward

Download and extract a suitable executable from
[Releases](https://github.com/radkesvat/WaterWall/releases), or build it using the
instructions below. The following Linux example assumes the executable is named
`Waterwall` in your working directory. Python 3 and curl are only used to provide
and test a local HTTP service.

Create `core.json` to tell WaterWall which node configuration to load:

```json
{
  "misc": {
    "workers": 1,
    "ram-profile": "client",
    "tcp-tune": false,
    "try-enabling-bbr": false
  },
  "configs": ["forward.json"]
}
```

Create `forward.json` in the same directory:

```json
{
  "name": "local-forward",
  "nodes": [
    {
      "name": "entry",
      "type": "TcpListener",
      "settings": {"address": "127.0.0.1", "port": 8080},
      "next": "service"
    },
    {
      "name": "service",
      "type": "TcpConnector",
      "settings": {"address": "127.0.0.1", "port": 9000}
    }
  ]
}
```

Start a test HTTP service in one terminal:

```bash
python3 -m http.server 9000 --bind 127.0.0.1
```

In a second terminal, run WaterWall from the directory containing both JSON files:

```bash
chmod +x ./Waterwall
./Waterwall
```

In a third terminal, request the service through WaterWall:

```bash
curl http://127.0.0.1:8080/
```

The response comes from the HTTP service on port `9000`, forwarded through
WaterWall's listener on port `8080`. This example stays on loopback and disables
host TCP tuning. Relative configuration paths are resolved from the process's
working directory.

Continue with the [installation and configuration guide](https://radkesvat.github.io/WaterWall-Docs/docs/getting-started/installation)
for deployment, logging, and more complete setups.

## Documentation

The full user manual, node reference, deployment examples, and developer guides
live in the **[WaterWall-Docs repository](https://github.com/radkesvat/WaterWall-Docs)**.
Read them on the published site in
[English](https://radkesvat.github.io/WaterWall-Docs/docs/intro) or
[Persian / فارسی](https://radkesvat.github.io/WaterWall-Docs/fa/docs/intro).

- [Core settings](https://radkesvat.github.io/WaterWall-Docs/docs/getting-started/tutorial-part1): workers, logging, DNS, and runtime configuration.
- [Config files and chains](https://radkesvat.github.io/WaterWall-Docs/docs/getting-started/tutorial-part3): node names, links, and complete configurations.
- [Choosing nodes](https://radkesvat.github.io/WaterWall-Docs/docs/getting-started/tutorial-part4): selecting compatible layers for your use case.
- [All nodes](https://radkesvat.github.io/WaterWall-Docs/docs/noderefs/all-nodes): settings and examples for individual nodes.
- [Developer guide](https://radkesvat.github.io/WaterWall-Docs/docs/devguides/doc1): architecture, tunnel contracts, and implementation workflow.

## Build from source

For the standard Linux preset, prepare:

- A C/C++ toolchain with C++20 support and the usual development libraries, including the static `libatomic` archive.
- Git, CMake **3.25 or newer**, Ninja, ccache, Perl, and make.
- Bash, Python 3, `ip` (iproute2), `unshare` (util-linux), and `readelf` (binutils), required by the default test configuration.

Then run:

```bash
git clone https://github.com/radkesvat/WaterWall.git
cd WaterWall
cmake --preset linux
cmake --build --preset linux -j8
```

The executable is produced at `build/linux/Release/Waterwall`. The first
configuration downloads dependencies, so it needs network access.

The default x64 build targets Haswell-class CPUs. For older processors or other
platforms, choose an appropriate preset from [CMakePresets.json](CMakePresets.json)
and its included files. Presets are provided for Linux, Windows, macOS, Android,
and iOS. See the [build and test guide](https://radkesvat.github.io/WaterWall-Docs/docs/devguides/part6-build-test-review)
for toolchain details and validation commands.

## Contributing

Bug reports, configuration examples, documentation improvements, and code
contributions are welcome. Open an [issue](https://github.com/radkesvat/WaterWall/issues)
with the WaterWall version, platform, steps to reproduce, and relevant logs and
configuration with secrets removed.

Before changing the runtime or adding a node, read the
[developer guide](https://radkesvat.github.io/WaterWall-Docs/docs/devguides/doc1)
and [contributor instructions](AGENTS.md). They describe the contracts that let
nodes compose safely and the checks expected for changes.

## Support WaterWall

If WaterWall is useful to you, consider supporting its development and
maintenance with a donation.

**[Support WaterWall](https://radkesvat-support.vercel.app/)**


Thanks for the support! ❤

## License

WaterWall is licensed under the [Mozilla Public License 2.0](LICENSE.txt).
Third-party dependencies retain their respective licenses.
