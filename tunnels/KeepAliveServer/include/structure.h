#pragma once

#include "wwapi.h"

typedef struct keepaliveserver_tstate_s
{
    int unused;
} keepaliveserver_tstate_t;

typedef struct keepaliveserver_lstate_s
{
    buffer_stream_t read_stream;
} keepaliveserver_lstate_t;

enum
{
    kKeepAliveServerFrameLengthSize     = sizeof(uint16_t),
    kKeepAliveServerFrameTypeSize       = sizeof(uint8_t),
    kKeepAliveServerFramePrefixSize     = kKeepAliveServerFrameLengthSize + kKeepAliveServerFrameTypeSize,
    kKeepAliveServerMaxFrameBodyLength  = UINT16_MAX,
    kKeepAliveServerMaxPayloadChunkSize = UINT16_MAX - 1,
    kKeepAliveServerReadOverflowLimit   = 131074,
    kKeepAliveServerFrameKindNormal     = 1,
    kKeepAliveServerFrameKindPing       = 2,
    kKeepAliveServerFrameKindPong       = 3,
    kTunnelStateSize                    = sizeof(keepaliveserver_tstate_t),
    kLineStateSize                      = sizeof(keepaliveserver_lstate_t)
};

WW_EXPORT void         keepaliveserverTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *keepaliveserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t keepaliveserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void keepaliveserverTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void keepaliveserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void keepaliveserverTunnelOnPrepair(tunnel_t *t);
void keepaliveserverTunnelOnStart(tunnel_t *t);
void keepaliveserverTunnelOnStop(tunnel_t *t);

void keepaliveserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void keepaliveserverTunnelUpStreamEst(tunnel_t *t, line_t *l);
void keepaliveserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void keepaliveserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void keepaliveserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void keepaliveserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void keepaliveserverTunnelDownStreamInit(tunnel_t *t, line_t *l);
void keepaliveserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void keepaliveserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void keepaliveserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void keepaliveserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void keepaliveserverTunnelDownStreamResume(tunnel_t *t, line_t *l);

void keepaliveserverLinestateInitialize(keepaliveserver_lstate_t *ls, line_t *l);
void keepaliveserverLinestateDestroy(keepaliveserver_lstate_t *ls);

bool keepaliveserverSendNormalFrameDownstream(tunnel_t *t, line_t *l, sbuf_t *buf);
bool keepaliveserverConsumeUpstreamFrames(tunnel_t *t, line_t *l);
void keepaliveserverCloseLineFromUpstream(tunnel_t *t, line_t *l);
void keepaliveserverCloseLineFromDownstream(tunnel_t *t, line_t *l);
