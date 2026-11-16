#pragma once

#include "PingCommon/ping6_wire.h"
#include "wwapi.h"

typedef struct ping6client_tstate_s
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
} ping6client_tstate_t;

enum
{
    kPing6ClientEncapsulationOverhead = kPing6WireEncapsulationOverhead,
    kPing6ClientDefaultTtl            = 64,
    kPing6ClientDefaultTos            = 0,
    kPing6ClientDefaultSequenceStart  = 1,
};

WW_EXPORT void         ping6clientDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *ping6clientCreate(node_t *node);
WW_EXPORT api_result_t ping6clientApi(tunnel_t *instance, sbuf_t *message);

void ping6clientOnPrepair(tunnel_t *t);
void ping6clientOnStart(tunnel_t *t);

void ping6clientUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void ping6clientDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void ping6clientEncapsulatePacket(tunnel_t *t, line_t *l, sbuf_t *buf);
void ping6clientDecapsulatePacket(tunnel_t *t, line_t *l, sbuf_t *buf);
