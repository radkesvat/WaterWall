#pragma once

#include "wwapi.h"

#include "http2_def.h"
#include "http_def.h"
#include "nghttp2/nghttp2.h"

enum http2_actions
{
    kActionInvalid,
    kActionStreamEst,
    kActionStreamFinish,
    kActionStreamDataReceived,
    kActionConData
};

typedef struct http2_action_s
{
    enum http2_actions action_id;
    line_t            *stream_line;
    sbuf_t            *buf;

} http2_action_t;

#define i_type action_queue_t
#define i_key  http2_action_t
#include "stc/deque.h"

typedef struct http2_client_child_con_state_s
{
    struct http2_client_child_con_state_s *prev, *next;
    nghttp2_stream                        *ng_stream;
    buffer_stream_t                       *grpc_buffer_stream;
    tunnel_t                              *tunnel;
    line_t                                *parent;
    line_t                                *line;
    size_t                                 grpc_bytes_needed;
    int32_t                                stream_id;
    bool                                   paused;

} http2_client_child_con_state_t;

typedef struct httpclient_lstate_s
{
    http2_client_child_con_state_t root;
    context_queue_t                cq_u;
    context_queue_t                cq_d;
    buffer_queue_t                 bq;
    action_queue_t                 actions;
    nghttp2_session               *session;
    wtimer_t                      *ping_timer;
    tunnel_t                      *tunnel;
    line_t                        *line;
    line_t                        *current_stream_write_line;
    const char                    *path;
    const char                    *host; // authority
    const char                    *scheme;
    enum http_method               method;
    enum http_content_type         content_type;
    size_t                         childs_added;
    uint32_t                       pause_counter;
    int                            error;
    int                            frame_type_when_stream_closed;
    int                            host_port;
    bool                           handshake_completed;
    bool                           init_sent;
    bool                           no_ping_ack;
} httpclient_lstate_t;

#define i_type    vec_cons              // NOLINT
#define i_key     httpclient_lstate_t * // NOLINT
#define i_use_cmp                       // NOLINT
#include "stc/vec.h"

typedef struct thread_connection_pool_s
{
    vec_cons cons;
    size_t   round_index;
} thread_connection_pool_t;

typedef struct httpclient_tstate_s
{
    nghttp2_session_callbacks *cbs;
    nghttp2_option            *ngoptions;
    char                      *scheme;
    char                      *path;
    char                      *host; // authority
    enum http_content_type     content_type;
    size_t                     concurrency;
    int                        host_port;
    int                        last_iid;
    bool                       discard_settings_frame;

    thread_connection_pool_t thread_cpool[];
} httpclient_tstate_t;

enum
{
    kTunnelStateSize            = sizeof(httpclient_tstate_t),
    kLineStateSize              = sizeof(httpclient_lstate_t),
    kDefaultHttp2MuxConcurrency = 1
};

WW_EXPORT void         httpclientTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *httpclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t httpclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void httpclientTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void httpclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void httpclientTunnelOnPrepair(tunnel_t *t);
void httpclientTunnelOnStart(tunnel_t *t);

void httpclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void httpclientTunnelUpStreamEst(tunnel_t *t, line_t *l);
void httpclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void httpclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void httpclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void httpclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void httpclientTunnelDownStreamInit(tunnel_t *t, line_t *l);
void httpclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void httpclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void httpclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void httpclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void httpclientTunnelDownStreamResume(tunnel_t *t, line_t *l);

void httpclientLinestateInitialize(httpclient_lstate_t *ls);
void httpclientLinestateDestroy(httpclient_lstate_t *ls);

static void *httpclientNgh2CustomMemoryAllocate(size_t size, void *mem_user_data)
{
    discard mem_user_data;
    return memoryAllocate(size);
}

static void *httpclientNgh2CustomMemoryReAllocate(void *ptr, size_t size, void *mem_user_data)
{
    discard mem_user_data;
    return memoryReAllocate(ptr, size);
}
static void *httpclientNgh2CustomMemoryCalloc(size_t n, size_t size, void *mem_user_data)
{
    discard mem_user_data;
    return memoryCalloc(n, size);
}
static void httpclientNgh2CustomMemoryFree(void *ptr, void *mem_user_data)
{
    discard mem_user_data;
    memoryFree(ptr);
}

int httpclientV2OnHeaderCallBack(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name,
                                 size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *userdata);

int httpclientV2OnDataChunkRecvCallBack(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data,
                                        size_t len, void *userdata);

int httpclientV2OnFrameRecvCallBack(nghttp2_session *session, const nghttp2_frame *frame, void *userdata);

int httpclientV2OnStreamClosedCallBack(nghttp2_session *session, int32_t stream_id, uint32_t error_code,
                                       void *userdata);
