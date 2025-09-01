#pragma once

#include "wwapi.h"

#include "http2_def.h"
#include "http_def.h"
#include "nghttp2/nghttp2.h"

typedef struct httpclient_lstate_s
{
    context_queue_t cq;
    context_queue_t cq_d;

    buffer_queue_t bq;

    nghttp2_session *session;
    tunnel_t        *tunnel;
    line_t          *line;
    const char      *path;
    const char      *host; // authority
    const char      *scheme;

    enum http_method       method;
    enum http_content_type content_type;

    size_t childs_added;
    int    error;
    int    host_port;
    int    stream_id;
    bool   handshake_completed;
    bool   init_sent;
} httpclient_lstate_t;

typedef struct httpclient_tstate_s
{
    nghttp2_session_callbacks *cbs;
    nghttp2_option            *ngoptions;
    char                      *scheme;
    char                      *path;
    char                      *host; // authority
    enum http_content_type     content_type;
    int                        host_port;
    int                        last_iid;
    bool                       discard_settings_frame;

} httpclient_tstate_t;

enum
{
    kTunnelStateSize               = sizeof(httpclient_tstate_t),
    kLineStateSize                 = sizeof(httpclient_lstate_t),
    kHttpClientRequiredPaddingLeft = HTTP2_FRAME_HDLEN, // used in node.c
    kDefaultHttp2MuxConcurrency    = 1,
};

WW_EXPORT void         httpclientTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *httpclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t httpclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void httpclientTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void httpclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void httpclientTunnelOnPrepair(tunnel_t *t);
void httpclientTunnelOnStart(tunnel_t *t);

void httpclientV2TunnelUpStreamInit(tunnel_t *t, line_t *l);
void httpclientV2TunnelUpStreamEst(tunnel_t *t, line_t *l);
void httpclientV2TunnelUpStreamFinish(tunnel_t *t, line_t *l);
void httpclientV2TunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void httpclientV2TunnelUpStreamPause(tunnel_t *t, line_t *l);
void httpclientV2TunnelUpStreamResume(tunnel_t *t, line_t *l);

void httpclientV2TunnelDownStreamInit(tunnel_t *t, line_t *l);
void httpclientV2TunnelDownStreamEst(tunnel_t *t, line_t *l);
void httpclientV2TunnelDownStreamFinish(tunnel_t *t, line_t *l);
void httpclientV2TunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void httpclientV2TunnelDownStreamPause(tunnel_t *t, line_t *l);
void httpclientV2TunnelDownStreamResume(tunnel_t *t, line_t *l);

void httpclientV2LinestateInitialize(httpclient_lstate_t *ls, tunnel_t *t, wid_t wid);
void httpclientV2LinestateDestroy(httpclient_lstate_t *ls);

void takeHttp2Connection(httpclient_lstate_t *con, tunnel_t *t, wid_t wid);

sbuf_t *httpclientV2MakeFrame(bool is_grpc, unsigned int stream_id, sbuf_t *buf);

bool httpclientV2PullAndSendNgHttp2SendableData(tunnel_t *t, httpclient_lstate_t *ls);

int httpclientV2OnHeaderCallBack(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name,
                                 size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *userdata);

int httpclientV2OnDataChunkRecvCallBack(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data,
                                        size_t len, void *userdata);

int httpclientV2OnFrameRecvCallBack(nghttp2_session *session, const nghttp2_frame *frame, void *userdata);

int httpclientV2OnStreamClosedCallBack(nghttp2_session *session, int32_t stream_id, uint32_t error_code,
                                       void *userdata);

nghttp2_nv makeNV(const char *name, const char *value);

