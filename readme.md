# Waterwall 

![GitHub commit activity](https://img.shields.io/github/commit-activity/m/radkesvat/WaterWall)
[![CLang Static Analyzer](https://github.com/radkesvat/WaterWall/actions/workflows/clang_static_analyzer.yml/badge.svg)](https://github.com/radkesvat/WaterWall/actions/workflows/clang_static_analyzer.yml)

[![CI](https://github.com/radkesvat/WaterWall/actions/workflows/ci.yaml/badge.svg)](https://github.com/radkesvat/WaterWall/actions/workflows/ci.yaml)


A simple core for tunneling and even direct user-server connections. based on high-performance, fully customizeable nodes for creating any kind of protocol without writing code for it.

To start please read the [docs](https://radkesvat.github.io/WaterWall-Docs/). (The documents are currently only in Persian language.)

# News

A number of new nodes have been added and they seem to be functioning well without any issues.

🔒 TlsClient
Performs SSL handshakes using the exact latest Google Chrome JA4 TLS fingerprint.

🔀 MuxClient / MuxServer
Standalone multiplexing implementation.

Supports both time-based and count-based muxing strategies.

🔁 HalfDuplexClient / HalfDuplexServer
Completely rewritten from the previous version.


🔄 TcpOverUdpClient / TcpOverUdpServer
Enables tunneling of TCP traffic over UDP (or raw Wire in general).

🔁 UdpOverTcpClient / UdpOverTcpServer
Enables tunneling of UDP-based protocols (like WireGuard or L2TP) over TCP.

🛠️ Additional Features
Support for port range listening. (Tcp and Udp)

Support for random UDP port connections.

I still need to test them more, and if i dont find any bugs they will be released soon!


# Donation

Those who are willing to support the continuation of the project can send donations to this TRX wallet.


```
TJpNiqtg3ddkrToUxm6tGhEaoaU9i1UK5c
```

<!-- # Plan

- [x] Restructure the project into a much cleaner design  
- [ ] Remove OpenSSL/WolfSSL client, create a TLS client using curl-impersonate  
- [ ] Rework OpenSSL server, configure options to match Nginx identically  
- [ ] Focus on HTTP/1 or HTTP/2, make every option configurable via JSON  
- [ ] Redesign Layer 3 nodes with a different architecture  
- [x] Add support for WireGuard  
- [ ] Add support for Router  
- [ ] Implement more transports like HTTP/3 or a stream control node  
 -->
<!-- 



Thanks for the support! ❤ -->
