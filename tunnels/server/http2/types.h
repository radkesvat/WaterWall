#pragma once
#include "api.h"
#include "nghttp2/nghttp2.h"
#include "buffer_stream.h"
#include "http_def.h"
#include "http2_def.h"
#include "grpc_def.h"

#define STATE(x) ((http2_server_state_t *)((x)->state))
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


typedef struct http2_server_child_con_state_s
{
    struct http2_server_child_con_state_s *prev, *next;
    char *request_path;
    int32_t stream_id;

    line_t *parent;
    line_t *line;
    hio_t* io;
    tunnel_t *tunnel;
} http2_server_child_con_state_t;

typedef struct http2_server_con_state_s
{

    nghttp2_session *session;
    http2_session_state state;
    int error;
    int frame_type_when_stream_closed;
    enum http_content_type content_type;

    tunnel_t *tunnel;
    line_t *line;
    hio_t* io;
    http2_server_child_con_state_t root;

} http2_server_con_state_t;



typedef struct http2_server_state_s
{
    nghttp2_session_callbacks *cbs;
    tunnel_t *fallback;
    nghttp2_option * ngoptions;

} http2_server_state_t;
