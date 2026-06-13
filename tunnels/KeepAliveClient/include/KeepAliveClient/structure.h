#pragma once

#include "wwapi.h"

typedef struct keepaliveclient_lstate_s keepaliveclient_lstate_t;

typedef struct keepaliveclient_tstate_s
{
    wmutex_t                  lines_mutex;
    keepaliveclient_lstate_t *lines_head;
    wtimer_t                **worker_timers;
    uint32_t                  ping_interval_ms;
} keepaliveclient_tstate_t;

struct keepaliveclient_lstate_s
{
    buffer_stream_t           read_stream;
    line_t                   *line;
    keepaliveclient_lstate_t *tracked_prev;
    keepaliveclient_lstate_t *tracked_next;
    wid_t                     wid;
};

enum
{
    kKeepAliveFrameLengthSize     = sizeof(uint16_t),
    kKeepAliveFrameTypeSize       = sizeof(uint8_t),
    kKeepAliveFramePrefixSize     = kKeepAliveFrameLengthSize + kKeepAliveFrameTypeSize,
    kKeepAliveMaxFrameBodyLength  = UINT16_MAX,
    kKeepAliveMaxPayloadChunkSize = UINT16_MAX - 1,
    kKeepAliveReadOverflowLimit   = 131074,
    kKeepAliveFrameKindNormal     = 1,
    kKeepAliveFrameKindPing       = 2,
    kKeepAliveFrameKindPong       = 3,
    kKeepAliveDefaultPingMs       = 60000,
    kTunnelStateSize              = sizeof(keepaliveclient_tstate_t),
    kLineStateSize                = sizeof(keepaliveclient_lstate_t)
};

WW_EXPORT void         keepaliveclientTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *keepaliveclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t keepaliveclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void keepaliveclientTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void keepaliveclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void keepaliveclientTunnelOnPrepair(tunnel_t *t);
void keepaliveclientTunnelOnStart(tunnel_t *t);
void keepaliveclientTunnelOnStop(tunnel_t *t);
void keepaliveclientTunnelOnWorkerStop(tunnel_t *t, wid_t wid);

void keepaliveclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void keepaliveclientTunnelUpStreamEst(tunnel_t *t, line_t *l);
void keepaliveclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void keepaliveclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void keepaliveclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void keepaliveclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void keepaliveclientTunnelDownStreamInit(tunnel_t *t, line_t *l);
void keepaliveclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void keepaliveclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void keepaliveclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void keepaliveclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void keepaliveclientTunnelDownStreamResume(tunnel_t *t, line_t *l);

void keepaliveclientLinestateInitialize(keepaliveclient_lstate_t *ls, line_t *l);
void keepaliveclientLinestateDestroy(keepaliveclient_lstate_t *ls);

void keepaliveclientTrackLine(tunnel_t *t, line_t *l);
void keepaliveclientUntrackLine(tunnel_t *t, line_t *l);
void keepaliveclientWorkerTimerCallback(wtimer_t *timer);

bool keepaliveclientSendPingFrame(tunnel_t *t, line_t *l);
bool keepaliveclientSendNormalFrameUpstream(tunnel_t *t, line_t *l, sbuf_t *buf);
bool keepaliveclientConsumeDownstreamFrames(tunnel_t *t, line_t *l);

void keepaliveclientCloseLineFromUpstream(tunnel_t *t, line_t *l);
void keepaliveclientCloseLineFromDownstream(tunnel_t *t, line_t *l);
