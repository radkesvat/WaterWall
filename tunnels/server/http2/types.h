#pragma once
#include "api.h"
#include "buffer_stream.h"

#include "http_def.h"
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
    kMaxSendBeforeAck = (1 << 20)
};

typedef struct http2_server_child_con_state_s
{
    struct http2_server_child_con_state_s *prev, *next;
    char                                  *request_path;
    int32_t                                stream_id;
    bool                                   first_sent;
    buffer_stream_t                       *chunkbs; // used for grpc
    size_t                                 bytes_needed;
    line_t                                *parent;
    line_t                                *line;
    tunnel_t                              *tunnel;
    size_t                                 bytes_sent_nack;
    size_t                                 bytes_received_nack;
} http2_server_child_con_state_t;

typedef struct http2_server_con_state_s
{

    nghttp2_session               *session;
    http2_session_state            state;
    uint32_t                       pause_counter;
    int                            error;
    int                            frame_type_when_stream_closed;
    enum http_content_type         content_type;
    tunnel_t                      *tunnel;
    line_t                        *line;
    http2_server_child_con_state_t root;

} http2_server_con_state_t;

typedef struct http2_server_state_s
{
    nghttp2_session_callbacks *cbs;
    tunnel_t                  *fallback;
    nghttp2_option            *ngoptions;

} http2_server_state_t;
