#pragma once

#include "wwapi.h"

#include "http2_def.h"
#include "http_def.h"
#include "nghttp2/nghttp2.h"

typedef struct httpserver_lstate_s
{
    context_queue_t        cq_u;
    nghttp2_session       *session;
    tunnel_t              *tunnel;
    line_t                *line;
    enum http_content_type content_type;
    int                    stream_id;
} httpserver_lstate_t;

typedef struct httpserver_tstate_s
{
    nghttp2_session_callbacks *cbs;
    nghttp2_option            *ngoptions;

} httpserver_tstate_t;

enum
{
    kTunnelStateSize               = sizeof(httpserver_tstate_t),
    kLineStateSize                 = sizeof(httpserver_lstate_t),
    kHttpServerRequiredPaddingLeft = HTTP2_FRAME_HDLEN, // used in node.c
    kDefaultHttp2MuxConcurrency    = 1,
};

WW_EXPORT void         httpserverTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *httpserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t httpserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void httpserverTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void httpserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void httpserverTunnelOnPrepair(tunnel_t *t);
void httpserverTunnelOnStart(tunnel_t *t);

void httpserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void httpserverTunnelUpStreamEst(tunnel_t *t, line_t *l);
void httpserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void httpserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void httpserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void httpserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void httpserverTunnelDownStreamInit(tunnel_t *t, line_t *l);
void httpserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void httpserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void httpserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void httpserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void httpserverTunnelDownStreamResume(tunnel_t *t, line_t *l);

void httpserverLinestateInitialize(httpserver_lstate_t *ls);
void httpserverLinestateDestroy(httpserver_lstate_t *ls);

void httpserverV2LinestateInitialize(httpserver_lstate_t *ls, tunnel_t *t, wid_t wid);
void httpserverV2LinestateDestroy(httpserver_lstate_t *ls);

sbuf_t *httpserverV2MakeFrame(bool is_grpc, unsigned int stream_id, sbuf_t *buf);

bool httpserverV2PullAndSendNgHttp2SendableData(tunnel_t *t, httpserver_lstate_t *ls);

int httpserverV2OnHeaderCallBack(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name,
                                 size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *userdata);

int httpserverV2OnDataChunkRecvCallBack(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data,
                                        size_t len, void *userdata);

int httpserverV2OnFrameRecvCallBack(nghttp2_session *session, const nghttp2_frame *frame, void *userdata);

int httpserverV2OnStreamClosedCallBack(nghttp2_session *session, int32_t stream_id, uint32_t error_code,
                                       void *userdata);
                                       
static inline nghttp2_nv makeNV(const char *name, const char *value)
{
    nghttp2_nv nv;
    nv.name     = (uint8_t *) name;
    nv.value    = (uint8_t *) value;
    nv.namelen  = stringLength(name);
    nv.valuelen = stringLength(value);
    nv.flags    = NGHTTP2_NV_FLAG_NONE;
    return nv;
}
