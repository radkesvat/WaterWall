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

} http2_server_con_state_t;

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
