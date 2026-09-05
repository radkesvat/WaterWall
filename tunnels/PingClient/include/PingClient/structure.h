#pragma once

#include "PingCommon/ping_wire.h"
#include "wwapi.h"

#include "loggers/log_rate_limiter.h"

typedef struct pingclient_tstate_s
{
    ping_wire_config_t             wire;
    ping_wire_tracker_t           *tracker;
    ping_wire_reply_id_generator_t reply_ids;
    atomic_uint                    next_sequence;
    atomic_log_rate_limiter_t      drop_log_limiter;
    uint8_t                        digest_key[WCRYPTO_BLAKE2S_MAX_KEY_SIZE];
    bool                           identifier_is_random;
    bool                           started;
} pingclient_tstate_t;

enum
{
    kPingClientEncapsulationOverhead = kPingWireEncapsulationOverhead,
    kPingClientDefaultTtl            = 64,
    kPingClientDefaultTos            = 0,
    kPingClientDefaultSequenceStart  = 1,
};

WW_EXPORT void         pingclientDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *pingclientCreate(node_t *node);
WW_EXPORT api_result_t pingclientApi(tunnel_t *instance, sbuf_t *message);

void pingclientOnIndex(tunnel_t *t, uint16_t index, uint32_t *mem_offset);
void pingclientOnChain(tunnel_t *t, tunnel_chain_t *chain);
void pingclientOnPrepair(tunnel_t *t);
void pingclientOnStart(tunnel_t *t);

void pingclientUpStreamInit(tunnel_t *t, line_t *l);
void pingclientUpStreamEst(tunnel_t *t, line_t *l);
void pingclientUpStreamFinish(tunnel_t *t, line_t *l);
void pingclientUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void pingclientUpStreamPause(tunnel_t *t, line_t *l);
void pingclientUpStreamResume(tunnel_t *t, line_t *l);

void pingclientDownStreamEst(tunnel_t *t, line_t *l);
void pingclientDownStreamFinish(tunnel_t *t, line_t *l);
void pingclientDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void pingclientDownStreamPause(tunnel_t *t, line_t *l);
void pingclientDownStreamResume(tunnel_t *t, line_t *l);

void pingclientEncapsulatePacket(tunnel_t *t, line_t *l, sbuf_t *buf);
void pingclientDecapsulatePacket(tunnel_t *t, line_t *l, sbuf_t *buf);
