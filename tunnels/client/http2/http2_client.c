#include "http2_client.h"
#include "nghttp2/nghttp2.h"
#include "buffer_stream.h"
#include "http_def.h"
#include "http2_def.h"
#include "grpc_def.h"
#include "loggers/network_logger.h"
#include "helpers.h"

#define STATE(x) ((http2_client_state_t *)((x)->state))
#define CSTATE(x) ((http2_client_con_state_t *)((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]
#define ISALIVE(x) (CSTATE(x) != NULL)

typedef struct http2_client_state_s
{
    nghttp2_session_callbacks *cbs;

    char *path;
    char *host; // authority
    int host_port;
    char *scheme;
    http_method method;

} http2_client_state_t;

typedef struct http2_client_con_state_s
{
    bool established;

    nghttp2_session *session;
    http2_session_state state;
    int error;
    int stream_id;
    int stream_closed;
    int frame_type_when_stream_closed;
    enum http_content_type content_type;

    // since nghttp2 uses callbacks
    tunnel_t *_self;
    line_t *line;

} http2_client_con_state_t;

static void cleanup(http2_client_con_state_t *cstate)
{
    tunnel_t *self = cstate->_self;
    nghttp2_session_set_user_data(cstate->session, NULL);
    nghttp2_session_del(cstate->session);
    cstate->line->chains_state[self->chain_index] = NULL;
    free(cstate);
}

static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame,
                              const uint8_t *_name, size_t namelen,
                              const uint8_t *_value, size_t valuelen,
                              uint8_t flags, void *userdata)
{
    if (userdata == NULL)
        return 0;

    LOGD("on_header_callback\n");
    print_frame_hd(&frame->hd);
    const char *name = (const char *)_name;
    const char *value = (const char *)_value;
    LOGD("%s: %s\n", name, value);

    http2_client_con_state_t *cstate = (http2_client_con_state_t *)userdata;
    tunnel_t *self = cstate->_self;

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
            cstate->content_type = http_content_type_enum(value);
        }
    }

    return 0;
}

static int on_data_chunk_recv_callback(nghttp2_session *session,
                                       uint8_t flags, int32_t stream_id, const uint8_t *data,
                                       size_t len, void *userdata)
{
    if (userdata == NULL)
        return 0;
    http2_client_con_state_t *cstate = (http2_client_con_state_t *)userdata;
    tunnel_t *self = cstate->_self;
    LOGD("on_data_chunk_recv_callback\n");
    LOGD("stream_id=%d length=%d\n", stream_id, (int)len);
    // LOGD("%.*s\n", (int)len, data);

    if (cstate->content_type == APPLICATION_GRPC)
    {
        // grpc_message_hd
        if (len >= GRPC_MESSAGE_HDLEN)
        {
            grpc_message_hd msghd;
            grpc_message_hd_unpack(&msghd, data);
            LOGD("grpc_message_hd: flags=%d length=%d\n", msghd.flags, msghd.length);
            data += GRPC_MESSAGE_HDLEN;
            len -= GRPC_MESSAGE_HDLEN;
            // LOGD("%.*s\n", (int)len, data);
        }
    }

    shift_buffer_t *buf = popBuffer(buffer_pools[cstate->line->tid]);
    shiftl(buf, lCap(buf) / 1.25); // use some unused space
    setLen(buf, len);
    memcpy(rawBuf(buf), data, len);
    context_t *up_data = newContext(cstate->line);
    up_data->payload = buf;
    self->up->upStream(self->up, up_data);
    // if (hp->parsed->http_cb)
    // {
    //     hp->parsed->http_cb(hp->parsed, HP_BODY, (const char *)data, len);
    // }
    // else
    // {
    //     hp->parsed->body.append((const char *)data, len);
    // }
    return 0;
}

static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *userdata)
{
    if (userdata == NULL)
        return 0;

    LOGD("on_frame_recv_callback\n");
    print_frame_hd(&frame->hd);
    http2_client_con_state_t *cstate = (http2_client_con_state_t *)userdata;
    tunnel_t *self = cstate->_self;

    switch (frame->hd.type)
    {
    case NGHTTP2_DATA:
        cstate->state = H2_RECV_DATA;
        break;
    case NGHTTP2_HEADERS:
        cstate->state = H2_RECV_HEADERS;
        break;
    case NGHTTP2_SETTINGS:
        cstate->state = H2_RECV_SETTINGS;
        break;
    case NGHTTP2_PING:
        cstate->state = H2_RECV_PING;
        break;
    case NGHTTP2_RST_STREAM:
    case NGHTTP2_WINDOW_UPDATE:
        // ignore
        return 0;
    default:
        break;
    }
    // if (cstate->state == H2_RECV_HEADERS && cstate->parsed->http_cb)
    // {
    //     cstate->parsed->http_cb(cstate->parsed, HP_HEADERS_COMPLETE, NULL, 0);
    // }
    if (frame->hd.stream_id >= cstate->stream_id)
    {
        cstate->stream_id = frame->hd.stream_id;
        cstate->stream_closed = 0;
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
        {
            LOGD("on_stream_closed stream_id=%d\n", cstate->stream_id);
            cstate->stream_closed = 1;
            cstate->frame_type_when_stream_closed = frame->hd.type;
            if (cstate->state == H2_RECV_HEADERS || cstate->state == H2_RECV_DATA)
            {
                //  upsteram end
                {
                    context_t *fin_ctx = newContext(cstate->line);
                    fin_ctx->fin = true;
                    self->up->upStream(self->up, fin_ctx);
                }

                context_t *fail_ctx = newContext(cstate->line);
                fail_ctx->fin = true;
                cleanup(cstate);
                self->dw->downStream(self->dw, fail_ctx);
                return -1;
                //  if (cstate->parsed->http_cb)
                //  {
                //      cstate->parsed->http_cb(cstate->parsed, HP_MESSAGE_COMPLETE, NULL, 0);
                //  }
            }
        }
        else
        {
            cstate->init_sent = true;
            context_t *init_ctx = newContext(cstate->line);
            init_ctx->init = true;
            self->up->upStream(self->up, init_ctx);
        }
    }

    return 0;
}

static bool trySendRequest(tunnel_t *self, line_t *line, shift_buffer_t **buf)
{
    // HTTP2_MAGIC,HTTP2_SETTINGS,HTTP2_HEADERS
    http2_client_con_state_t *cstate = ((http2_client_con_state_t *)(((line->chains_state)[self->chain_index])));
    if (cstate == NULL)
        return false;

    char *data = NULL;
    size_t len;
    len = nghttp2_session_mem_send(cstate->session, (const uint8_t **)&data);
    LOGD("nghttp2_session_mem_send %d\n", len);
    if (len != 0)
    {
        shift_buffer_t *send_buf = popBuffer(buffer_pools[line->tid]);
        shiftl(send_buf, lCap(send_buf) / 1.25); // use some unused space
        setLen(send_buf, len);
        memcpy(rawBuf(send_buf), data, len);
        context_t *answer = newContext(line);
        answer->payload = send_buf;
        self->up->upStream(self->up, answer);
        return true;
    }
    if (buf == NULL || *buf == NULL || bufLen(*buf) <= 0)
        return false;

    // HTTP2_DATA
    if (cstate->state == H2_SEND_HEADERS)
    {

        http2_flag flags = HTTP2_FLAG_END_STREAM;

        // HTTP2 DATA framehd
        cstate->state = H2_SEND_DATA;

        LOGD("HTTP2 SEND_DATA_FRAME_HD...\n");
        if (cstate->content_type == APPLICATION_GRPC)
        {
            grpc_message_hd msghd;
            msghd.flags = 0;
            msghd.length = bufLen(*buf);
            LOGD("grpc_message_hd: flags=%d length=%d\n", msghd.flags, msghd.length);

            // grpc server send grpc-status in HTTP2 header frame
            flags = HTTP2_FLAG_NONE;

            shiftl(*buf, GRPC_MESSAGE_HDLEN);

            grpc_message_hd_pack(&msghd, rawBuf(*buf));
        }
        http2_frame_hd framehd;

        framehd.length = bufLen(*buf);
        framehd.type = HTTP2_DATA;
        framehd.flags = flags;
        framehd.stream_id = cstate->stream_id;
        shiftl(*buf, HTTP2_FRAME_HDLEN);
        http2_frame_hd_pack(&framehd, rawBuf(*buf));
        context_t *answer = newContext(line);
        answer->payload = *buf;
        self->dw->downStream(self->dw, answer);

        return true;
    }
    else if (cstate->state == H2_SEND_DATA)
    {
    send_done:
        *buf = NULL;
        cstate->state = H2_SEND_DONE;
        if (cstate->content_type == APPLICATION_GRPC)
        {
            if (cstate->stream_closed)
            {
                // grpc HEADERS grpc-status
                LOGD("grpc HEADERS grpc-status: 0\n");
                int flags = NGHTTP2_FLAG_END_STREAM | NGHTTP2_FLAG_END_HEADERS;
                nghttp2_nv nv = make_nv("grpc-status", "0");
                nghttp2_submit_headers(cstate->session, flags, cstate->stream_id, NULL, &nv, 1, NULL);
                // len = nghttp2_session_mem_send(cstate->session, (const uint8_t **)&data);
                return true;
            }
        }
    }

    LOGD("GetSendData %d\n", len);
    return false;
}

static inline void upStream(tunnel_t *self, context_t *c)
{
    http2_client_state_t *state = STATE(self);
    if (c->payload != NULL)
    {
        http2_client_con_state_t *cstate = CSTATE(c);
        assert(cstate->established);

        cstate->state = H2_SEND_HEADERS;

        // consumes payload
        while (trySendRequest(self, c->line, &(c->payload)))
            ;
        assert(c->payload == NULL);
        destroyContext(c);
    }
    else
    {
        if (c->init)
        {
            CSTATE_MUT(c) = malloc(sizeof(http2_client_con_state_t));
            memset(CSTATE(c), 0, sizeof(http2_client_con_state_t));
            http2_client_con_state_t *cstate = CSTATE(c);
            nghttp2_session_client_new(&cstate->session, state->cbs, cstate);
            cstate->state = H2_WANT_RECV;
            cstate->stream_id = -1;
            cstate->stream_closed = 0;
            cstate->_self = self;
            cstate->line = c->line;

            nghttp2_settings_entry settings[] = {
                {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
            nghttp2_submit_settings(cstate->session, NGHTTP2_FLAG_NONE, settings, ARRAY_SIZE(settings));

            cstate->state = H2_SEND_MAGIC;
            self->up->upStream(self->up, c);
        }
        else if (c->fin)
        {
            cleanup(CSTATE(c));
            self->up->upStream(self->up, c);
        }
    }
}

static inline void downStream(tunnel_t *self, context_t *c)
{
    http2_client_state_t *state = STATE(self);
    http2_client_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {

        assert(cstate->established);

        cstate->state = H2_WANT_RECV;
        size_t len = bufLen(c->payload);
        size_t ret = nghttp2_session_mem_recv(cstate->session, (const uint8_t *)rawBuf(c->payload), len);
        DISCARD_CONTEXT(c);

        if (!ISALIVE(c))
        {
            destroyContext(c);
            return;
        }

        if (ret != len)
        {
            {
                context_t *fail_ctx = newContext(c->line);
                fail_ctx->fin = true;
                self->up->upStream(self->up, fail_ctx);
            }
            context_t *fail_ctx = newContext(c->line);
            fail_ctx->fin = true;
            cleanup(CSTATE(c));

            self->dw->downStream(self->dw, fail_ctx);
        }
        destroyContext(c);
    }
    else
    {
        if (c->est)
        {
            char authority_addr[320];

            // cstate->established = true;
            nghttp2_nv nvs[15];
            int nvlen = 0;
            if (cstate->content_type == APPLICATION_GRPC)
            {
                state->method = HTTP_POST;
            }

            make_nv(":status", "200");
            nvs[nvlen++] = make_nv(":method", http_method_str(state->method));
            nvs[nvlen++] = make_nv(":path", state->path);
            nvs[nvlen++] = make_nv(":scheme", state->scheme);
            if (state->port == 0 ||
                state->port == DEFAULT_HTTP_PORT ||
                state->port == DEFAULT_HTTPS_PORT)
            {
                nvs[nvlen++] = (make_nv(":authority", state->host));
            }
            else
            {
                snprintf(authority_addr, sizeof(authority_addr), "%s:%d", state->host, state->port);
                nvs[nvlen++] = (make_nv(":authority", authority_addr));
            }
            int flags = NGHTTP2_FLAG_END_HEADERS;
            // we set EOS on DATA frame
            stream_id = nghttp2_submit_headers(cstate->session, flags, -1, NULL, &nvs[0], nvlen, NULL);
            state = H2_SEND_HEADERS;
            while (trySendRequest())
                ;

            cstate->established = true;
        }
        else if (c->fin)
        {
            cleanup(CSTATE(c));
        }
        self->dw->downStream(self->dw, c);
    }
}

static void Http2ClientUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void Http2ClientPacketUpStream(tunnel_t *self, context_t *c)
{
    LOGF("Http2Client: Http2 protocol dose not run on udp");
    exit(1);
}
static void Http2ClientDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}
static void Http2ClientPacketDownStream(tunnel_t *self, context_t *c)
{
    LOGF("Http2Client: Http2 protocol dose not run on udp");
    exit(1);
}

tunnel_t *newHttp2Client(node_instance_context_t *instance_info)
{
    http2_client_state_t *state = malloc(sizeof(http2_client_state_t));
    memset(state, 0, sizeof(http2_client_state_t));
    cJSON *settings = instance_info->node_settings_json;

    nghttp2_session_callbacks_new(&(state->cbs));
    nghttp2_session_callbacks_set_on_header_callback(state->cbs, on_header_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(state->cbs, on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(state->cbs, on_frame_recv_callback);

    state->host = "app.launchdarkly.com";
    state->host_port = 443;
    // state->path = "/sdk/goals/50afa3d7607a72221591aeb73"
    state->scheme = "https" state->method = GET;

    tunnel_t *t = newTunnel();
    t->state = state;
    t->upStream = &Http2ClientUpStream;
    t->packetUpStream = &Http2ClientPacketUpStream;
    t->downStream = &Http2ClientDownStream;
    t->packetDownStream = &Http2ClientPacketDownStream;

    atomic_thread_fence(memory_order_release);
    return t;
}

api_result_t apiHttp2Client(tunnel_t *self, char *msg)
{
    LOGE("http2-server API NOT IMPLEMENTED");
    return (api_result_t){0}; // TODO
}

tunnel_t *destroyHttp2Client(tunnel_t *self)
{
    LOGE("http2-server DESTROY NOT IMPLEMENTED"); // TODO
    return NULL;
}

tunnel_metadata_t getMetadataHttp2Client()
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
