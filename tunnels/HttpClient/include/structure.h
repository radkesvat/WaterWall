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
    action_queue_t                 actions;
    nghttp2_session               *session;
    context_queue_t               *queue;
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
    thread_connection_pool_t   thread_cpool[];
} httpclient_tstate_t;

enum
{
    kTunnelStateSize = sizeof(httpclient_tstate_t),
    kLineStateSize   = sizeof(httpclient_lstate_t)
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
