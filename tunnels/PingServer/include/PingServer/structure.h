#pragma once

#include "PingCommon/ping_wire.h"
#include "wwapi.h"

#include "loggers/log_rate_limiter.h"

typedef struct pingserver_tstate_s
{
    ping_wire_config_t             wire;
    ping_wire_tracker_t           *tracker;
    ping_wire_reply_id_generator_t reply_ids;
    atomic_uint                    next_sequence;
    atomic_log_rate_limiter_t      drop_log_limiter;
    uint8_t                        digest_key[WCRYPTO_BLAKE2S_MAX_KEY_SIZE];
    bool                           identifier_is_random;
    bool                           started;
} pingserver_tstate_t;

enum
{
    kPingServerEncapsulationOverhead = kPingWireEncapsulationOverhead,
    kPingServerDefaultTtl            = 64,
    kPingServerDefaultTos            = 0,
    kPingServerDefaultSequenceStart  = 1,
};

WW_EXPORT void         pingserverDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *pingserverCreate(node_t *node);
WW_EXPORT api_result_t pingserverApi(tunnel_t *instance, sbuf_t *message);

void pingserverOnIndex(tunnel_t *t, uint16_t index, uint32_t *mem_offset);
void pingserverOnChain(tunnel_t *t, tunnel_chain_t *chain);
void pingserverOnPrepair(tunnel_t *t);
void pingserverOnStart(tunnel_t *t);

void pingserverUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void pingserverDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void pingserverHandleUpstreamPacket(tunnel_t *t, line_t *l, sbuf_t *buf);
void pingserverHandleDownstreamPacket(tunnel_t *t, line_t *l, sbuf_t *buf);
