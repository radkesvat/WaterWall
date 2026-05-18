#pragma once

#include "wwapi.h"
#include "lwip/prot/icmp.h"
#include "lwip/prot/ip4.h"

typedef struct pingclient_tstate_s
{
    atomic_uint icmp_sequence;
    atomic_uint ipv4_identification;
    uint16_t    identifier;
    uint32_t    source_addr;
    uint32_t    dest_addr;
    bool        source_addr_configured;
    bool        dest_addr_configured;
    uint8_t     ttl;
    uint8_t     tos;
    uint8_t     strategy;
    uint8_t     swap_protocol;
    uint8_t     payload_xor_byte;
    bool        payload_xor_enabled;
    bool        roundup_payload_size;
} pingclient_tstate_t;

typedef struct pingclient_lstate_s
{
    int unused;
} pingclient_lstate_t;

enum
{
    kPingClientStrategyWrapNewIpAndIcmpHeader = 1,
    kPingClientStrategyWrapIcmpHeaderAndReuseIpv4Addrs,
    kPingClientStrategyWrapOnlyIcmpHeader,
    kPingClientStrategyChangeOnlyIpv4ProtocolNumber,

    kPingClientNetworkMtu            = kMaxAllowedPacketLength,
    kPingClientIpv4HeaderLength      = sizeof(struct ip_hdr),
    kPingClientIcmpHeaderLength      = sizeof(struct icmp_echo_hdr),
    kPingClientEncapsulationOverhead = kPingClientIpv4HeaderLength + kPingClientIcmpHeaderLength,
    kPingClientSizePrefixLength      = sizeof(uint16_t),
    kPingClientReuseTrailerLength    = 5,
    kPingClientMaxIcmpPayloadLength  = kPingClientNetworkMtu - kPingClientEncapsulationOverhead,
    kPingClientMaxOnlyIcmpPayloadLength = kPingClientNetworkMtu - kPingClientIcmpHeaderLength,
    kPingClientMaxInnerPacketLength  = kPingClientMaxIcmpPayloadLength,
    kPingClientDefaultIdentifier     = 0xAFAF,
    kPingClientDefaultTtl            = 64,
    kTunnelStateSize                 = sizeof(pingclient_tstate_t),
    kLineStateSize                   = sizeof(pingclient_lstate_t)
};

WW_EXPORT void         pingclientDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *pingclientCreate(node_t *node);
WW_EXPORT api_result_t pingclientApi(tunnel_t *instance, sbuf_t *message);

void pingclientOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void pingclientOnChain(tunnel_t *t, tunnel_chain_t *chain);
void pingclientOnPrepair(tunnel_t *t);
void pingclientOnStart(tunnel_t *t);

void pingclientUpStreamInit(tunnel_t *t, line_t *l);
void pingclientUpStreamEst(tunnel_t *t, line_t *l);
void pingclientUpStreamFinish(tunnel_t *t, line_t *l);
void pingclientUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void pingclientUpStreamPause(tunnel_t *t, line_t *l);
void pingclientUpStreamResume(tunnel_t *t, line_t *l);

void pingclientDownStreamInit(tunnel_t *t, line_t *l);
void pingclientDownStreamEst(tunnel_t *t, line_t *l);
void pingclientDownStreamFinish(tunnel_t *t, line_t *l);
void pingclientDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void pingclientDownStreamPause(tunnel_t *t, line_t *l);
void pingclientDownStreamResume(tunnel_t *t, line_t *l);

void pingclientLinestateInitialize(pingclient_lstate_t *ls);
void pingclientLinestateDestroy(pingclient_lstate_t *ls);

void pingclientEncapsulatePacket(tunnel_t *t, line_t *l, sbuf_t *buf);
void pingclientDecapsulatePacket(tunnel_t *t, line_t *l, sbuf_t *buf);
