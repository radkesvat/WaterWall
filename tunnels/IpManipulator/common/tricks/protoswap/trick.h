#pragma once
#include "structure.h"

/*****************************************************************************
| Protocol Number | Protocol Name                                            |
|-----------------|----------------------------------------------------------|
| 1               | ICMP (Internet Control Message Protocol)                 |
| 2               | IGMP (Internet Group Management Protocol)                |
| 6               | TCP (Transmission Control Protocol)                      |
| 8               | EGP (Exterior Gateway Protocol)                          |
| 17              | UDP (User Datagram Protocol)                             |
| 27              | RDP (Reliable Datagram Protocol)                         |
| 33              | DCCP (Datagram Congestion Control Protocol)              |
| 41              | IPv6 encapsulation                                       |
| 43              | Fragment Header for IPv6                                 |
| 44              | RSVP (Resource Reservation Protocol)                     |
| 47              | GRE (Generic Routing Encapsulation)                      |
| 50              | ESP (Encapsulating Security Payload)                     |
| 51              | AH (Authentication Header)                               |
| 58              | ICMPv6 (ICMP for IPv6)                                   |
| 59              | No Next Header for IPv6                                  |
| 60              | Destination Options for IPv6                             |
| 88              | EIGRP (Enhanced Interior Gateway Routing Protocol)       |
| 89              | OSPF (Open Shortest Path First)                          |
| 94              | IPIP (IP-in-IP encapsulation)                            |
| 103             | PIM (Protocol Independent Multicast)                     |
| 108             | PCAP (Packet Capture)                                    |
| 112             | VRRP (Virtual Router Redundancy Protocol)                |
| 115             | L2TP (Layer 2 Tunneling Protocol)                        |
| 124             | ISIS (Intermediate System to Intermediate System)        |
| 132             | SCTP (Stream Control Transmission Protocol)              |
| 133             | FC (Fibre Channel)                                       |
| 136             | UDPLite (Lightweight User Datagram Protocol)             |
| 137             | MPLS-in-IP (Multiprotocol Label Switching encapsulation) |
| 138             | MANET (Mobile Ad Hoc Networks)                           |
| 139             | HIP (Host Identity Protocol)                             |
| 140             | Shim6 (Site Multihoming by IPv6 Intermediation)          |
| 141             | WESP (Wrapped Encapsulating Security Payload)            |
| 142             | ROHC (Robust Header Compression)                         |
| 253             | Use for experimentation and testing (RFC 3692)           |
| 254             | Use for experimentation and testing (RFC 3692)           |
| 255             | Reserved                                                 |
*****************************************************************************/

void protoswaptrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void protoswaptrickDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
