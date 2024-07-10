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

enum
{

    kMaxRecvBeforeAck = (1 << 16),
    kMaxSendBeforeAck = (1 << 19)
};

typedef struct http2_client_child_con_state_s
{
    struct http2_client_child_con_state_s *prev, *next;
    nghttp2_stream                        *ng_stream;
    buffer_stream_t                       *grpc_buffer_stream;
    tunnel_t                              *tunnel;
    line_t                                *parent;
    line_t                                *line;
    size_t                                 grpc_bytes_needed;
    size_t                                 bytes_sent_nack;
    size_t                                 bytes_received_nack;
    int32_t                                stream_id;

} http2_client_child_con_state_t;

typedef struct http2_client_con_state_s
{
    http2_session_state            state;
    http2_client_child_con_state_t root;
    nghttp2_session               *session;
    context_queue_t               *queue;
    htimer_t                      *ping_timer;
    tunnel_t                      *tunnel;
    line_t                        *line;
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
    bool                           first_sent;
    bool                           no_ping_ack;

} http2_client_con_state_t;

#define i_type    vec_cons                   // NOLINT
#define i_key     http2_client_con_state_t * // NOLINT
#define i_use_cmp                            // NOLINT
#include "stc/vec.h"

typedef struct thread_connection_pool_s
{
    vec_cons cons;
    size_t   round_index;
} thread_connection_pool_t;

typedef struct http2_client_state_s
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
} http2_client_state_t;
