#pragma once

#include "lwip/prot/icmp.h"
#include "lwip/prot/ip4.h"
#include "wwapi.h"

typedef struct pingserver_tstate_s
{
    atomic_uint icmp_sequence;
    atomic_uint ipv4_identification;
    uint16_t    identifier;
    bool        identifier_check_enabled;
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
} pingserver_tstate_t;

typedef struct pingserver_lstate_s
{
    int unused;
} pingserver_lstate_t;

enum
{
    kPingServerStrategyWrapNewIpAndIcmpHeader = 1,
    kPingServerStrategyWrapIcmpHeaderAndReuseIpv4Addrs,
    kPingServerStrategyWrapOnlyIcmpHeader,
    kPingServerStrategyChangeOnlyIpv4ProtocolNumber,
    kPingServerDefaultStrategy = kPingServerStrategyWrapIcmpHeaderAndReuseIpv4Addrs,

    kPingServerIpv4HeaderLength         = sizeof(struct ip_hdr),
    kPingServerIcmpHeaderLength         = sizeof(struct icmp_echo_hdr),
    kPingServerEncapsulationOverhead    = kPingServerIpv4HeaderLength + kPingServerIcmpHeaderLength,
    kPingServerSizePrefixLength         = sizeof(uint16_t),
    kPingServerReuseTrailerLength       = 5,
    kPingServerMaxIcmpPayloadLength     = kMaxAllowedPacketLength - kPingServerEncapsulationOverhead,
    kPingServerMaxOnlyIcmpPayloadLength = kMaxAllowedPacketLength - kPingServerIcmpHeaderLength,
    kPingServerMaxInnerPacketLength     = kPingServerMaxIcmpPayloadLength,
    kPingServerDefaultIdentifier        = 0xAFAF,
    kPingServerDefaultTtl               = 64,
    kPingServerDefaultTos               = 0,
    kPingServerDefaultSequenceStart     = 0,
    kPingServerDefaultIpv4IdStart       = 0,
    kPingServerDefaultPayloadXorByte    = -1,
    kPingServerDefaultRoundupPayload    = false,
    kPingServerDefaultIdentifierCheck   = true,
    kTunnelStateSize                    = sizeof(pingserver_tstate_t),
    kLineStateSize                      = sizeof(pingserver_lstate_t)
};

WW_EXPORT void         pingserverDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *pingserverCreate(node_t *node);
WW_EXPORT api_result_t pingserverApi(tunnel_t *instance, sbuf_t *message);

void pingserverOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void pingserverOnChain(tunnel_t *t, tunnel_chain_t *chain);
void pingserverOnPrepair(tunnel_t *t);
void pingserverOnStart(tunnel_t *t);
void pingserverOnStop(tunnel_t *t);

void pingserverUpStreamInit(tunnel_t *t, line_t *l);
void pingserverUpStreamEst(tunnel_t *t, line_t *l);
void pingserverUpStreamFinish(tunnel_t *t, line_t *l);
void pingserverUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void pingserverUpStreamPause(tunnel_t *t, line_t *l);
void pingserverUpStreamResume(tunnel_t *t, line_t *l);

void pingserverDownStreamInit(tunnel_t *t, line_t *l);
void pingserverDownStreamEst(tunnel_t *t, line_t *l);
void pingserverDownStreamFinish(tunnel_t *t, line_t *l);
void pingserverDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void pingserverDownStreamPause(tunnel_t *t, line_t *l);
void pingserverDownStreamResume(tunnel_t *t, line_t *l);

void pingserverLinestateInitialize(pingserver_lstate_t *ls);
void pingserverLinestateDestroy(pingserver_lstate_t *ls);

void pingserverHandleOutboundPacket(tunnel_t *t, line_t *l, sbuf_t *buf);
void pingserverHandleInboundPacket(tunnel_t *t, line_t *l, sbuf_t *buf);
