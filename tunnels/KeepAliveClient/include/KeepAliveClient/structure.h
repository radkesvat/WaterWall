#pragma once

#include "wwapi.h"

typedef struct keepaliveclient_lstate_s keepaliveclient_lstate_t;

typedef struct keepaliveclient_worker_state_s
{
    /* Quiescence stops expiry; the last borrowed line releases its table. */
    local_idle_table_t *idle_table;
    size_t              active_lines;
    bool                quiesced;
} keepaliveclient_worker_state_t;

typedef struct keepaliveclient_tstate_s
{
    uint32_t                       ping_interval_ms;
    uint32_t                       tolerance_ms;
    bool                           sensitive_mode;
    keepaliveclient_worker_state_t worker_states[];
} keepaliveclient_tstate_t;

struct keepaliveclient_lstate_s
{
    splice_stream_t   *read_stream;
    buffer_pool_t     *pool;
    buffer_queue_t     write_reentry;
    sbuf_t            *write_active;
    bool               read_draining;
    bool               write_draining;
    bool               write_paused;
    bool               pong_draining;
    uint32_t           pending_pongs;
    bool               established;
    bool               awaiting_pong;
    uint64_t           next_ping_at_ms;
    uint64_t           pong_deadline_ms;
    line_t            *line;
    tunnel_t          *tunnel;
    local_idle_item_t *ping_item;
    local_idle_item_t *pong_deadline_item;
};

enum
{
    kKeepAliveFrameLengthSize     = sizeof(uint32_t),
    kKeepAliveFrameTypeSize       = sizeof(uint8_t),
    kKeepAliveFramePrefixSize     = kKeepAliveFrameLengthSize + kKeepAliveFrameTypeSize,
    kKeepAliveMaxPayloadChunkSize = 6U * 1024U * 1024U,
    kKeepAliveMaxFrameBodyLength  = kKeepAliveMaxPayloadChunkSize + kKeepAliveFrameTypeSize,
    kKeepAliveReadOverflowLimit   = kKeepAliveMaxPayloadChunkSize + kKeepAliveFramePrefixSize,
    kKeepAliveReadChargeLimit     = 16U * 1024U * 1024U,
    kKeepAliveMaxReentryBytes     = 8U * 1024U * 1024U,
    kKeepAliveMaxReentryBuffers   = 1024U,
    kKeepAliveMaxPendingPongs     = 1024U,
    kKeepAliveFrameKindNormal     = 1,
    kKeepAliveFrameKindPing       = 2,
    kKeepAliveFrameKindPong       = 3,
    kKeepAliveDefaultPingMs       = 30000,
    kKeepAliveDefaultToleranceMs  = 90000,
    kKeepAlivePingRetryMs         = 1000,
    kTunnelStateSize              = sizeof(keepaliveclient_tstate_t),
    kLineStateSize                = sizeof(keepaliveclient_lstate_t)
};

WW_EXPORT void         keepaliveclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *keepaliveclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t keepaliveclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void keepaliveclientTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);

void keepaliveclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void keepaliveclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void keepaliveclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void keepaliveclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void keepaliveclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void keepaliveclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void keepaliveclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void keepaliveclientTunnelDownStreamResume(tunnel_t *t, line_t *l);
void keepaliveclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void keepaliveclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void keepaliveclientLinestateInitialize(keepaliveclient_lstate_t *ls, line_t *l);
void keepaliveclientLinestateDestroy(keepaliveclient_lstate_t *ls);

void keepaliveclientTrackLine(tunnel_t *t, line_t *l);
void keepaliveclientUntrackLine(tunnel_t *t, line_t *l);

bool keepaliveclientSendPingFrame(tunnel_t *t, line_t *l);
bool keepaliveclientSendNormalFrameUpstream(tunnel_t *t, line_t *l, sbuf_t *buf);
bool keepaliveclientConsumeDownstreamFrames(tunnel_t *t, line_t *l);

void keepaliveclientCloseLineFromUpstream(tunnel_t *t, line_t *l);
void keepaliveclientCloseLineFromDownstream(tunnel_t *t, line_t *l);
void keepaliveclientCloseLineFromProtocolError(tunnel_t *t, line_t *l);
