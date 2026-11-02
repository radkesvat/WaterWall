#pragma once

#include "wwapi.h"

typedef struct keepaliveserver_lstate_s
{
    splice_frame_reader_t reader;
    buffer_pool_t        *pool;
    buffer_queue_t        write_reentry;
    sbuf_t               *write_active;
    bool                  write_draining;
} keepaliveserver_lstate_t;

enum
{
    kKeepAliveServerFrameLengthSize     = sizeof(uint32_t),
    kKeepAliveServerFrameTypeSize       = sizeof(uint8_t),
    kKeepAliveServerFramePrefixSize     = kKeepAliveServerFrameLengthSize + kKeepAliveServerFrameTypeSize,
    kKeepAliveServerMaxPayloadChunkSize = 1024U * 1024U,
    kKeepAliveServerMaxFrameBodyLength  = kKeepAliveServerMaxPayloadChunkSize + kKeepAliveServerFrameTypeSize,
    kKeepAliveServerReadChargeLimit     = 16U * 1024U * 1024U,
    kKeepAliveServerMaxReentryBytes     = 8U * 1024U * 1024U,
    kKeepAliveServerMaxReentryCharge    = 16U * 1024U * 1024U,
    kKeepAliveServerFrameKindNormal     = 1,
    kKeepAliveServerFrameKindPing       = 2,
    kKeepAliveServerFrameKindPong       = 3,
    kTunnelStateSize                    = 0,
    kLineStateSize                      = sizeof(keepaliveserver_lstate_t)
};

WW_EXPORT tunnel_t    *keepaliveserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t keepaliveserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void keepaliveserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void keepaliveserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void keepaliveserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void keepaliveserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void keepaliveserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void keepaliveserverLinestateInitialize(keepaliveserver_lstate_t *ls, line_t *l, bool splice_output);
void keepaliveserverLinestateDestroy(keepaliveserver_lstate_t *ls);

void keepaliveserverSendNormalFrameDownstream(tunnel_t *t, line_t *l, sbuf_t *buf);
void keepaliveserverConsumeUpstreamFrames(tunnel_t *t, line_t *l);
void keepaliveserverCloseLineFromUpstream(tunnel_t *t, line_t *l);
void keepaliveserverCloseLineFromDownstream(tunnel_t *t, line_t *l);
void keepaliveserverCloseLineFromProtocolError(tunnel_t *t, line_t *l);
