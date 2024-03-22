#pragma once

#include "nghttp2/nghttp2.h"
#include "buffer_stream.h"
#include "http_def.h"
#include "http2_def.h"
#include "grpc_def.h"
#include "loggers/network_logger.h"

#define STATE(x) ((http2_client_state_t *)((x)->state))
#define CSTATE(x) ((void *)((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]
#define ISALIVE(x) (CSTATE(x) != NULL)

typedef enum
{
    H2_SEND_MAGIC,
    H2_SEND_SETTINGS,
    H2_SEND_PING,
    H2_SEND_HEADERS,
    H2_SEND_DATA_FRAME_HD,
    H2_SEND_DATA,
    H2_SEND_DONE,

    H2_WANT_SEND,
    H2_WANT_RECV,

    H2_RECV_SETTINGS,
    H2_RECV_PING,
    H2_RECV_HEADERS,
    H2_RECV_DATA,
} http2_session_state;

typedef struct http2_client_child_con_state_s
{
    struct http2_client_child_con_state_s *prev, *next;
    int32_t stream_id;

    tunnel_t *tunnel;
    line_t *parent;
    line_t *line;
} http2_client_child_con_state_t;

typedef struct http2_client_con_state_s
{

    nghttp2_session *session;
    http2_session_state state;
    context_queue_t *queue;

    int error;
    int frame_type_when_stream_closed;
    bool handshake_completed;

    enum http_method method;
    enum http_content_type content_type;
    const char *path;
    const char *host; // authority
    int host_port;
    const char *scheme;
    bool init_sent;

    tunnel_t *tunnel;
    line_t *line;
    http2_client_child_con_state_t root;

} http2_client_con_state_t;

#define i_type vec_cons
#define i_key http2_client_con_state_t*
#define i_use_cmp
#include "stc/vec.h"

typedef struct thread_connection_pool_s
{
    size_t round_index;
    vec_cons cons;
} thread_connection_pool_t;

typedef struct http2_client_state_s
{
    nghttp2_session_callbacks *cbs;
    enum http_content_type content_type;

    char *path;
    char *host; // authority
    int host_port;
    char *scheme;
    int last_iid;
    thread_connection_pool_t thread_cpool[];
} http2_client_state_t;
