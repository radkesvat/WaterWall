#pragma once

#include "wwapi.h"
#include "lwip/prot/ip4.h"

typedef struct packetreceiver_source_range_s
{
    uint32_t base_host;
    uint64_t count;
    uint8_t  prefix_length;
    uint8_t  _padding[7];
} packetreceiver_source_range_t;

typedef struct packetreceiver_tstate_s
{
    packetreceiver_source_range_t *source_ranges;
    uint32_t                      source_range_count;
    uint64_t                      source_count;
    uint32_t                      expected_packets_per_ip;
    uint64_t                      total_expected_packets;
    uint64_t                      total_received_packets;
    uint64_t                      total_lost_packets;
    uint64_t                      unexpected_packets;
    wid_t                         workers_count;
    uint64_t                     *received_counts;
    char                         *output_file;
    uint32_t                      report_after_ms;
    wmutex_t                      state_mutex;
    bool                          report_written;
    bool                          report_in_progress;
} packetreceiver_tstate_t;

typedef struct packetreceiver_lstate_s
{
    int unused;
} packetreceiver_lstate_t;

enum
{
    kPacketReceiverHistogramWidth = 32,
    kTunnelStateSize              = sizeof(packetreceiver_tstate_t),
    kLineStateSize                = 0
};

WW_EXPORT void         packetreceiverTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *packetreceiverTunnelCreate(node_t *node);

void packetreceiverTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void packetreceiverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void packetreceiverTunnelOnPrepair(tunnel_t *t);
void packetreceiverTunnelOnStart(tunnel_t *t);

void packetreceiverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void packetreceiverTunnelUpStreamEst(tunnel_t *t, line_t *l);
void packetreceiverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void packetreceiverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void packetreceiverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void packetreceiverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void packetreceiverTunnelDownStreamInit(tunnel_t *t, line_t *l);
void packetreceiverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void packetreceiverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void packetreceiverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void packetreceiverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void packetreceiverTunnelDownStreamResume(tunnel_t *t, line_t *l);

void packetreceiverPrepareRuntime(tunnel_t *t);
void packetreceiverHandlePacket(tunnel_t *t, line_t *l, sbuf_t *buf);
void packetreceiverFinalizeReport(tunnel_t *t, bool terminate_after_write);
void packetreceiverReportTimerTask(void *worker, void *arg1, void *arg2, void *arg3);
