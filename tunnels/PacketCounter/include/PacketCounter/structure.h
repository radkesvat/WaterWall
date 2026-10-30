#pragma once

#include "lwip/prot/ip4.h"
#include "wwapi.h"

typedef struct packetcounter_source_range_s
{
    uint32_t base_host;
    uint64_t count;
    uint8_t  prefix_length;
    uint8_t  _padding[7];
} packetcounter_source_range_t;

typedef struct packetcounter_tstate_s
{
    packetcounter_source_range_t  *source_ranges;
    uint32_t                       source_range_count;
    uint64_t                       source_count;
    uint32_t                       expected_packets_per_ip;
    uint16_t                       protocol_count;
    uint8_t                        protocol_numbers[256];
    uint16_t                       protocol_slots[256];
    uint64_t                       total_expected_packets;
    uint64_t                       total_received_packets;
    uint64_t                       total_lost_packets;
    uint64_t                       unexpected_packets;
    wid_t                          workers_count;
    uint64_t                      *received_counts;
    char                          *output_file;
    uint32_t                       report_after_ms;
    wmutex_t                       state_mutex;
    bool                           report_written;
    bool                           report_in_progress;
} packetcounter_tstate_t;

typedef struct packetcounter_lstate_s
{
    int unused;
} packetcounter_lstate_t;

enum
{
    kPacketCounterHistogramWidth  = 32,
    kTunnelStateSize              = sizeof(packetcounter_tstate_t),
    kLineStateSize                = 0
};

WW_EXPORT void      packetcounterTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t *packetcounterTunnelCreate(node_t *node);

void packetcounterTunnelOnPrepair(tunnel_t *t);
void packetcounterTunnelOnStart(tunnel_t *t);

void packetcounterTunnelUpStreamInit(tunnel_t *t, line_t *l);
void packetcounterTunnelUpStreamEst(tunnel_t *t, line_t *l);
void packetcounterTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void packetcounterTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void packetcounterTunnelUpStreamPause(tunnel_t *t, line_t *l);
void packetcounterTunnelUpStreamResume(tunnel_t *t, line_t *l);

void packetcounterTunnelDownStreamInit(tunnel_t *t, line_t *l);
void packetcounterTunnelDownStreamEst(tunnel_t *t, line_t *l);
void packetcounterTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void packetcounterTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void packetcounterTunnelDownStreamPause(tunnel_t *t, line_t *l);
void packetcounterTunnelDownStreamResume(tunnel_t *t, line_t *l);

void packetcounterPrepareRuntime(tunnel_t *t);
void packetcounterHandlePacket(tunnel_t *t, line_t *l, sbuf_t *buf);
void packetcounterFinalizeReport(tunnel_t *t, bool terminate_after_write);
void packetcounterReportTimerTask(void *worker, void *arg1, void *arg2, void *arg3);
