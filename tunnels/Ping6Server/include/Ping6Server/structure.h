#pragma once

#include "PingCommon/ping6_wire.h"
#include "wwapi.h"

typedef struct ping6server_tstate_s
{
    ping6_wire_config_t            wire;
    ping_wire_tracker_t           *tracker;
    ping_wire_reply_id_generator_t reply_ids;
    atomic_uint                    next_sequence;
    atomic_log_rate_limiter_t      drop_log_limiter;
    uint8_t                        digest_key[WCRYPTO_BLAKE2S_MAX_KEY_SIZE];
    bool                           identifier_is_random;
    bool                           send_replies;
    bool                           started;
} ping6server_tstate_t;

enum
{
    kPing6ServerEncapsulationOverhead = kPing6WireEncapsulationOverhead,
    kPing6ServerDefaultTtl            = 64,
    kPing6ServerDefaultTos            = 0,
    kPing6ServerDefaultSequenceStart  = 1,
};

WW_EXPORT void         ping6serverDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *ping6serverCreate(node_t *node);
WW_EXPORT api_result_t ping6serverApi(tunnel_t *instance, sbuf_t *message);

void ping6serverOnPrepair(tunnel_t *t);
void ping6serverOnStart(tunnel_t *t);

void ping6serverUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void ping6serverDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void ping6serverHandleUpstreamPacket(tunnel_t *t, line_t *l, sbuf_t *buf);
void ping6serverHandleDownstreamPacket(tunnel_t *t, line_t *l, sbuf_t *buf);
