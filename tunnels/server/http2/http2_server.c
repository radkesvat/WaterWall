#include "http2_server.h"
#include "nghttp2/nghttp2.h"
#include "buffer_stream.h"
#include "http2_def.h"
#include "grpc_def.h"
#include "loggers/network_logger.h"

#define STATE(x) ((http2_server_state_t *)((x)->state))
#define CSTATE(x) ((http2_server_con_state_t *)((((x)->line->chains_state)[self->chain_index])))
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

typedef struct http2_server_state_s
{
    nghttp2_session_callbacks *cbs;
    tunnel_t *fallback;

} http2_server_state_t;

typedef struct http2_server_con_state_s
{
    bool init_sent;
    bool first_sent;

    nghttp2_session *session;
    http2_session_state state;
    int error;
    int stream_id;
    int stream_closed;
    int frame_type_when_stream_closed;
    // http2_frame_hd + grpc_message_hd
    // at least HTTP2_FRAME_HDLEN + GRPC_MESSAGE_HDLEN = 9 + 5 = 14
    unsigned char frame_hdbuf[32];

} http2_server_con_state_t;




static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame,
                              const uint8_t *_name, size_t namelen,
                              const uint8_t *_value, size_t valuelen,
                              uint8_t flags, void *userdata)
{
    printd("on_header_callback\n");
    print_frame_hd(&frame->hd);
    const char *name = (const char *)_name;
    const char *value = (const char *)_value;
    printd("%s: %s\n", name, value);
    if (*name == ':')
    {
        if (strcmp(name, ":method") == 0)
        {
            // req->method = http_method_enum(value);
        }
        else if (strcmp(name, ":path") == 0)
        {
            // req->url = value;
        }
        else if (strcmp(name, ":scheme") == 0)
        {
            // req->headers["Scheme"] = value;
        }
        else if (strcmp(name, ":authority") == 0)
        {
            // req->headers["Host"] = value;
        }
    }
    else
    {
        // hp->parsed->headers[name] = value;
        if (strcmp(name, "content-type") == 0)
        {
            // hp->parsed->content_type = http_content_type_enum(value);
        }
    }
    
    return 0;
    
}

static int on_data_chunk_recv_callback(nghttp2_session *session,
                                       uint8_t flags, int32_t stream_id, const uint8_t *data,
                                       size_t len, void *userdata)
{
    printd("on_data_chunk_recv_callback\n");
    printd("stream_id=%d length=%d\n", stream_id, (int)len);
    // printd("%.*s\n", (int)len, data);
    Http2Parser *hp = (Http2Parser *)userdata;

    if (hp->parsed->ContentType() == APPLICATION_GRPC)
    {
        // grpc_message_hd
        if (len >= GRPC_MESSAGE_HDLEN)
        {
            grpc_message_hd msghd;
            grpc_message_hd_unpack(&msghd, data);
            printd("grpc_message_hd: flags=%d length=%d\n", msghd.flags, msghd.length);
            data += GRPC_MESSAGE_HDLEN;
            len -= GRPC_MESSAGE_HDLEN;
            // printd("%.*s\n", (int)len, data);
        }
    }
    if (hp->parsed->http_cb)
    {
        hp->parsed->http_cb(hp->parsed, HP_BODY, (const char *)data, len);
    }
    else
    {
        hp->parsed->body.append((const char *)data, len);
    }
    return 0;
}

static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *userdata)
{
    printd("on_frame_recv_callback\n");
    print_frame_hd(&frame->hd);
    Http2Parser *hp = (Http2Parser *)userdata;
    switch (frame->hd.type)
    {
    case NGHTTP2_DATA:
        hp->state = H2_RECV_DATA;
        break;
    case NGHTTP2_HEADERS:
        hp->state = H2_RECV_HEADERS;
        break;
    case NGHTTP2_SETTINGS:
        hp->state = H2_RECV_SETTINGS;
        break;
    case NGHTTP2_PING:
        hp->state = H2_RECV_PING;
        break;
    case NGHTTP2_RST_STREAM:
    case NGHTTP2_WINDOW_UPDATE:
        // ignore
        return 0;
    default:
        break;
    }
    if (hp->state == H2_RECV_HEADERS && hp->parsed->http_cb)
    {
        hp->parsed->http_cb(hp->parsed, HP_HEADERS_COMPLETE, NULL, 0);
    }
    if (frame->hd.stream_id >= hp->stream_id)
    {
        hp->stream_id = frame->hd.stream_id;
        hp->stream_closed = 0;
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
        {
            printd("on_stream_closed stream_id=%d\n", hp->stream_id);
            hp->stream_closed = 1;
            hp->frame_type_when_stream_closed = frame->hd.type;
            if (hp->state == H2_RECV_HEADERS || hp->state == H2_RECV_DATA)
            {
                if (hp->parsed->http_cb)
                {
                    hp->parsed->http_cb(hp->parsed, HP_MESSAGE_COMPLETE, NULL, 0);
                }
            }
        }
    }

    return 0;
}

static inline void upStream(tunnel_t *self, context_t *c)
{
    http2_server_state_t *state = STATE(self);
    if (c->payload != NULL)
    {
        http2_server_con_state_t *cstate = CSTATE(c);
    }
    else
    {
        if (c->init)
        {
            CSTATE_MUT(c) = malloc(sizeof(http2_server_con_state_t));
            memset(CSTATE(c), 0, sizeof(http2_server_con_state_t));
            http2_server_con_state_t *cstate = CSTATE(c);
            destroyContext(c);
        }
        else if (c->fin)
        {
            bool init_sent = CSTATE(c)->init_sent;
            free(CSTATE(c));
            CSTATE_MUT(c) = NULL;
            if (init_sent)
                self->up->upStream(self->up, c);
            else
                destroyContext(c);
        }
    }
}

static inline void downStream(tunnel_t *self, context_t *c)
{
    if (c->fin)
    {
        free(CSTATE(c));
        CSTATE_MUT(c) = NULL;
    }
    self->dw->downStream(self->dw, c);

    return;
}

static void http2ServerUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void http2ServerPacketUpStream(tunnel_t *self, context_t *c)
{
    LOGF("Http2Server: Http2 protocol dose not run on udp");
    exit(1);
}
static void http2ServerDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}
static void http2ServerPacketDownStream(tunnel_t *self, context_t *c)
{
    LOGF("Http2Server: Http2 protocol dose not run on udp");
    exit(1);
}

tunnel_t *newHttp2Server(node_instance_context_t *instance_info)
{
    http2_server_state_t *state = malloc(sizeof(http2_server_state_t));
    memset(state, 0, sizeof(http2_server_state_t));
    cJSON *settings = instance_info->node_settings_json;

    nghttp2_session_callbacks_new(&(state->cbs));
    // nghttp2_session_callbacks_set_on_header_callback(state->cbs, on_header_callback);
    // nghttp2_session_callbacks_set_on_data_chunk_recv_callback(state->cbs, on_data_chunk_recv_callback);
    // nghttp2_session_callbacks_set_on_frame_recv_callback(state->cbs, on_frame_recv_callback);

    tunnel_t *t = newTunnel();
    t->state = state;
    t->upStream = &http2ServerUpStream;
    t->packetUpStream = &http2ServerPacketUpStream;
    t->downStream = &http2ServerDownStream;
    t->packetDownStream = &http2ServerPacketDownStream;

    atomic_thread_fence(memory_order_release);
    return t;
}

api_result_t apiHttp2Server(tunnel_t *self, char *msg)
{
    LOGE("http2-server API NOT IMPLEMENTED");
    return (api_result_t){0}; // TODO
}

tunnel_t *destroyHttp2Server(tunnel_t *self)
{
    LOGE("http2-server DESTROY NOT IMPLEMENTED"); // TODO
    return NULL;
}

tunnel_metadata_t getMetadataHttp2Server()
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
