#pragma once
#include "api.h"
#include "buffer_stream.h"

#include "http_def.h"
#include "nghttp2/nghttp2.h"


enum
{
    kMaxRecvBeforeAck = (1 << 16),
    kMaxSendBeforeAck = (1 << 19)
};

enum http2_actions
{
    kActionInvalid,
    kActionStreamInit,
    kActionStreamFinish,
    kActionStreamDataReceived,
    kActionConData
    // kActionConFinish
};

typedef struct http2_action_s
{
    enum http2_actions action_id;
    line_t            *stream_line;
    shift_buffer_t    *buf;

} http2_action_t;

#define i_TYPE action_queue_t, http2_action_t // NOLINT
#include "stc/deq.h"

typedef struct http2_server_child_con_state_s
{
    struct http2_server_child_con_state_s *prev, *next;
    char                                  *request_path;
    buffer_stream_t                       *grpc_buffer_stream;
    line_t                                *parent;
    line_t                                *line;
    tunnel_t                              *tunnel;
    size_t                                 bytes_sent_nack;
    size_t                                 bytes_received_nack;
    size_t                                 grpc_bytes_needed;
    int32_t                                stream_id;
    bool                                   first_sent;

} http2_server_child_con_state_t;

typedef struct http2_server_con_state_s
{
    http2_server_child_con_state_t root;
    action_queue_t                 actions;
    nghttp2_session               *session;
    tunnel_t                      *tunnel;
    line_t                        *line;
    enum http_content_type         content_type;
    uint32_t                       pause_counter;
    int                            error;
    int                            frame_type_when_stream_closed;

} http2_server_con_state_t;

typedef struct http2_server_state_s
{
    nghttp2_session_callbacks *cbs;
    tunnel_t                  *fallback;
    nghttp2_option            *ngoptions;

} http2_server_state_t;
