#pragma once

#include "wwapi.h"


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

typedef struct ipmanipulator_tstate_s
{
    int manip_swap_tcp;
} ipmanipulator_tstate_t;

typedef struct ipmanipulator_lstate_s
{
    int unused;
} ipmanipulator_lstate_t;

enum
{
    kTunnelStateSize = sizeof(ipmanipulator_tstate_t),
    kLineStateSize   = sizeof(ipmanipulator_lstate_t)
};

WW_EXPORT void         ipmanipulatorDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *ipmanipulatorCreate(node_t *node);
WW_EXPORT api_result_t ipmanipulatorApi(tunnel_t *instance, sbuf_t *message);

void ipmanipulatorOnIndex(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset);
void ipmanipulatorOnChain(tunnel_t *t, tunnel_chain_t *chain);
void ipmanipulatorOnPrepair(tunnel_t *t);
void ipmanipulatorOnStart(tunnel_t *t);

void ipmanipulatorUpStreamInit(tunnel_t *t, line_t *l);
void ipmanipulatorUpStreamEst(tunnel_t *t, line_t *l);
void ipmanipulatorUpStreamFinish(tunnel_t *t, line_t *l);
void ipmanipulatorUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void ipmanipulatorUpStreamPause(tunnel_t *t, line_t *l);
void ipmanipulatorUpStreamResume(tunnel_t *t, line_t *l);

void ipmanipulatorDownStreamInit(tunnel_t *t, line_t *l);
void ipmanipulatorDownStreamEst(tunnel_t *t, line_t *l);
void ipmanipulatorDownStreamFinish(tunnel_t *t, line_t *l);
void ipmanipulatorDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void ipmanipulatorDownStreamPause(tunnel_t *t, line_t *l);
void ipmanipulatorDownStreamResume(tunnel_t *t, line_t *l);

void ipmanipulatorLinestateInitialize(ipmanipulator_lstate_t *ls);
void ipmanipulatorLinestateDestroy(ipmanipulator_lstate_t *ls);
