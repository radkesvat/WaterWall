#pragma once

#include "wwapi.h"
#include "lwip/prot/icmp.h"
#include "lwip/prot/ip4.h"
#include "lwip/prot/tcp.h"
#include "lwip/prot/udp.h"

typedef struct packetsender_worker_state_s
{
    tunnel_t *tunnel;
    line_t   *line;
    wtimer_t *timer;
    uint64_t  packet_index_begin;
    uint64_t  packet_index_end;
    uint64_t  next_packet_index;
    wid_t     wid;
} packetsender_worker_state_t;

typedef struct packetsender_tstate_s
{
    uint32_t source_base_host;
    uint32_t dest_addr_host;
    uint32_t dest_addr_network;
    uint32_t duration_ms;
    uint16_t dest_port;
    uint16_t src_port;
    uint8_t  source_prefix_length;
    uint8_t  protocol_mode;
    bool     src_port_random;
    uint8_t  _padding0;

    atomic_uint completed_workers;

    uint64_t source_count;
    uint64_t total_packets;
    size_t   total_packet_bytes;
    size_t   bytes_per_source;

    uint16_t fixed_packet_length;
    uint16_t protocol_lengths[255];
    uint32_t protocol_offsets[256];

    uint8_t                    *packet_bytes;
    packetsender_worker_state_t *workers;
    wid_t                       workers_count;
    wid_t                       active_workers;
    uint64_t                    schedule_start_ms;
} packetsender_tstate_t;

typedef struct packetsender_lstate_s
{
    int unused;
} packetsender_lstate_t;

enum packetsender_protocol_mode_e
{
    kPacketSenderProtocolTcp = 1,
    kPacketSenderProtocolUdp,
    kPacketSenderProtocolIcmp,
    kPacketSenderProtocolAll
};

enum
{
    kPacketSenderProtocolsPerSource   = 255,
    kPacketSenderIpv4HeaderLength     = sizeof(struct ip_hdr),
    kPacketSenderTcpHeaderLength      = sizeof(struct tcp_hdr),
    kPacketSenderUdpHeaderLength      = sizeof(struct udp_hdr),
    kPacketSenderIcmpHeaderLength     = sizeof(struct icmp_echo_hdr),
    kPacketSenderGenericPayloadLength = 8,
    kPacketSenderGenericPacketLength  = kPacketSenderIpv4HeaderLength + kPacketSenderGenericPayloadLength,
    kPacketSenderTcpPacketLength      = kPacketSenderIpv4HeaderLength + kPacketSenderTcpHeaderLength,
    kPacketSenderUdpPacketLength      = kPacketSenderIpv4HeaderLength + kPacketSenderUdpHeaderLength,
    kPacketSenderIcmpPacketLength     = kPacketSenderIpv4HeaderLength + kPacketSenderIcmpHeaderLength,
    kPacketSenderDefaultTtl           = 64,
    kPacketSenderRandomPortMin        = 49152,
    kPacketSenderRandomPortMax        = 65535,
    kPacketSenderRandomPortSpan       = (kPacketSenderRandomPortMax - kPacketSenderRandomPortMin) + 1,
    kPacketSenderMaxMaterializedBytes = 512U * 1024U * 1024U,
    kTunnelStateSize                  = sizeof(packetsender_tstate_t),
    kLineStateSize                    = 0
};

WW_EXPORT void         packetsenderTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *packetsenderTunnelCreate(node_t *node);
WW_EXPORT api_result_t packetsenderTunnelApi(tunnel_t *instance, sbuf_t *message);

void packetsenderTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void packetsenderTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void packetsenderTunnelOnPrepair(tunnel_t *t);
void packetsenderTunnelOnStart(tunnel_t *t);

void packetsenderTunnelUpStreamInit(tunnel_t *t, line_t *l);
void packetsenderTunnelUpStreamEst(tunnel_t *t, line_t *l);
void packetsenderTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void packetsenderTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void packetsenderTunnelUpStreamPause(tunnel_t *t, line_t *l);
void packetsenderTunnelUpStreamResume(tunnel_t *t, line_t *l);

void packetsenderTunnelDownStreamInit(tunnel_t *t, line_t *l);
void packetsenderTunnelDownStreamEst(tunnel_t *t, line_t *l);
void packetsenderTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void packetsenderTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void packetsenderTunnelDownStreamPause(tunnel_t *t, line_t *l);
void packetsenderTunnelDownStreamResume(tunnel_t *t, line_t *l);

void packetsenderLinestateInitialize(packetsender_lstate_t *ls);
void packetsenderLinestateDestroy(packetsender_lstate_t *ls);

void packetsenderPrepareRuntime(tunnel_t *t);
void packetsenderStartWorker(void *worker_ptr, void *arg1, void *arg2, void *arg3);
void packetsenderWorkerTimerCallback(wtimer_t *timer);
void packetsenderHandleUnexpectedDownstreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
