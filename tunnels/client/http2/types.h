#pragma once
#include "api.h"
#include "buffer_stream.h"
#include "grpc_def.h"
#include "http2_def.h"
#include "http_def.h"
#include "loggers/network_logger.h"
#include "nghttp2/nghttp2.h"

typedef enum
{
    kH2SendMagic,
    kH2SendSettings,
    kH2SendPing,
    kH2SendHeaders,
    kH2SendDataFrameHd,
    kH2SendData,
    kH2SendDone,
    kH2WantSend,
    kH2WantRecv,
    kH2RecvSettings,
    kH2RecvPing,
    kH2RecvHeaders,
    kH2RecvData,
} http2_session_state;

typedef struct http2_client_child_con_state_s
{
    struct http2_client_child_con_state_s *prev, *next;
    int32_t                                stream_id;
    nghttp2_stream                        *ng_stream;
    buffer_stream_t                       *chunkbs; // used for grpc
    size_t                                 bytes_needed;
    tunnel_t                              *tunnel;
    line_t                                *parent;
    line_t                                *line;

} http2_client_child_con_state_t;

typedef struct http2_client_con_state_s
{

    nghttp2_session               *session;
    http2_session_state            state;
    context_queue_t               *queue;
    size_t                         childs_added;
    uint32_t                       pause_counter;
    int                            error;
    int                            frame_type_when_stream_closed;
    bool                           handshake_completed;
    enum http_method               method;
    enum http_content_type         content_type;
    const char                    *path;
    const char                    *host; // authority
    int                            host_port;
    const char                    *scheme;
    bool                           init_sent;
    bool                           first_sent;
    bool                           no_ping_ack;
    htimer_t                      *ping_timer;
    tunnel_t                      *tunnel;
    line_t                        *line;
    http2_client_child_con_state_t root;

} http2_client_con_state_t;

#define i_type    vec_cons                   // NOLINT
#define i_key     http2_client_con_state_t * // NOLINT
#define i_use_cmp                            // NOLINT
#include "stc/vec.h"

typedef struct thread_connection_pool_s
{
    size_t   round_index;
    vec_cons cons;
} thread_connection_pool_t;

typedef struct http2_client_state_s
{
    nghttp2_session_callbacks *cbs;
    enum http_content_type     content_type;
    size_t                     concurrency;
    char                      *path;
    char                      *host; // authority
    int                        host_port;
    char                      *scheme;
    int                        last_iid;
    nghttp2_option            *ngoptions;
    thread_connection_pool_t   thread_cpool[];
} http2_client_state_t;
