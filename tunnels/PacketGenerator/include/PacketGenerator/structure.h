#pragma once

#include "lwip/prot/icmp.h"
#include "lwip/prot/ip4.h"
#include "lwip/prot/tcp.h"
#include "lwip/prot/udp.h"
#include "wwapi.h"

typedef struct packetgenerator_worker_state_s
{
    tunnel_t *tunnel;
    line_t   *line;
    wtimer_t *timer;
    uint64_t  packet_index_begin;
    uint64_t  packet_index_end;
    uint64_t  next_packet_index;
    wid_t     wid;
    bool      stopped;
} packetgenerator_worker_state_t;

typedef struct packetgenerator_source_range_s
{
    uint32_t base_host;
    uint64_t count;
    uint8_t  prefix_length;
    uint8_t  _padding[7];
} packetgenerator_source_range_t;

typedef struct packetgenerator_tstate_s
{
    packetgenerator_source_range_t *source_ranges;
    uint32_t                     source_range_count;
    uint32_t                     dest_addr_host;
    uint32_t                     dest_addr_network;
    uint32_t                     duration_ms;
    uint16_t                     dest_port;
    uint16_t                     src_port;
    uint8_t                      protocol_mode;
    bool                         src_port_random;
    uint8_t                      _padding0;

    atomic_uint completed_workers;

    uint32_t source_count;
    uint32_t packets_per_ip;
    uint64_t total_packets;
    size_t   total_packet_bytes;
    size_t   bytes_per_source;
    size_t   bytes_per_source_repeat;

    uint16_t fixed_packet_length;
    uint16_t protocol_lengths[255];
    uint32_t protocol_offsets[256];

    uint8_t                     *packet_bytes;
    packetgenerator_worker_state_t *workers;
    wid_t                        workers_count;
    wid_t                        active_workers;
    uint64_t                     schedule_start_ms;
} packetgenerator_tstate_t;

typedef struct packetgenerator_lstate_s
{
    int unused;
} packetgenerator_lstate_t;

enum packetgenerator_protocol_mode_e
{
    kPacketGeneratorProtocolTcp = 1,
    kPacketGeneratorProtocolUdp,
    kPacketGeneratorProtocolIcmp,
    kPacketGeneratorProtocolAll
};

enum
{
    kPacketGeneratorProtocolsPerSource   = 255,
    kPacketGeneratorIpv4HeaderLength     = sizeof(struct ip_hdr),
    kPacketGeneratorTcpHeaderLength      = sizeof(struct tcp_hdr),
    kPacketGeneratorUdpHeaderLength      = sizeof(struct udp_hdr),
    kPacketGeneratorIcmpHeaderLength     = sizeof(struct icmp_echo_hdr),
    kPacketGeneratorGenericPayloadLength = 8,
    kPacketGeneratorGenericPacketLength  = kPacketGeneratorIpv4HeaderLength + kPacketGeneratorGenericPayloadLength,
    kPacketGeneratorTcpPacketLength      = kPacketGeneratorIpv4HeaderLength + kPacketGeneratorTcpHeaderLength,
    kPacketGeneratorUdpPacketLength      = kPacketGeneratorIpv4HeaderLength + kPacketGeneratorUdpHeaderLength,
    kPacketGeneratorIcmpPacketLength     = kPacketGeneratorIpv4HeaderLength + kPacketGeneratorIcmpHeaderLength,
    kPacketGeneratorDefaultTtl           = 64,
    kPacketGeneratorRandomPortMin        = 49152,
    kPacketGeneratorRandomPortMax        = 65535,
    kPacketGeneratorRandomPortSpan       = (kPacketGeneratorRandomPortMax - kPacketGeneratorRandomPortMin) + 1,
    kTunnelStateSize                     = sizeof(packetgenerator_tstate_t),
    kLineStateSize                    = 0
};

static const uint64_t kPacketGeneratorMaxMaterializedBytes =
    UINT64_C(8) * UINT64_C(1024) * UINT64_C(1024) * UINT64_C(1024);

WW_EXPORT void         packetgeneratorTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *packetgeneratorTunnelCreate(node_t *node);
WW_EXPORT api_result_t packetgeneratorTunnelApi(tunnel_t *instance, sbuf_t *message);

void packetgeneratorTunnelOnPrepair(tunnel_t *t);
void packetgeneratorTunnelOnStart(tunnel_t *t);

void packetgeneratorTunnelDownStreamInit(tunnel_t *t, line_t *l);
void packetgeneratorTunnelDownStreamEst(tunnel_t *t, line_t *l);
void packetgeneratorTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void packetgeneratorTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void packetgeneratorTunnelDownStreamPause(tunnel_t *t, line_t *l);
void packetgeneratorTunnelDownStreamResume(tunnel_t *t, line_t *l);

void packetgeneratorLinestateInitialize(packetgenerator_lstate_t *ls);
void packetgeneratorLinestateDestroy(packetgenerator_lstate_t *ls);

void packetgeneratorPrepareRuntime(tunnel_t *t);
void packetgeneratorStopWorker(packetgenerator_worker_state_t *slot);
void packetgeneratorStartWorker(void *worker_ptr, void *arg1, void *arg2, void *arg3);
void packetgeneratorWorkerTimerCallback(wtimer_t *timer);
void packetgeneratorHandleUnexpectedDownstreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void packetgeneratorTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
