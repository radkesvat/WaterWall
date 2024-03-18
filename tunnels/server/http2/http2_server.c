#include "http2_server.h"

#include "types.h"
#include "helpers.h"
#include "loggers/network_logger.h"



static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code, void *userdata)
{

    if (userdata == NULL)
        return 0;

    http2_server_con_state_t *cstate = (http2_server_con_state_t *)userdata;
    tunnel_t *self = cstate->tunnel;

    http2_server_child_con_state_t *stream;
    (void)error_code;

    stream = nghttp2_session_get_stream_user_data(cstate->session, stream_id);
    if (!stream)
    {
        return 0;
    }
    remove_stream(cstate, stream);
    delete_http2_stream(stream);
    return 0;
}

static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame,
                              const uint8_t *_name, size_t namelen,
                              const uint8_t *_value, size_t valuelen,
                              uint8_t flags, void *userdata)
{
    if (userdata == NULL)
        return 0;

    // LOGD("on_header_callback\n");
    print_frame_hd(&frame->hd);
    const char *name = (const char *)_name;
    const char *value = (const char *)_value;
    // LOGD("%s: %s\n", name, value);

    http2_server_con_state_t *cstate = (http2_server_con_state_t *)userdata;
    tunnel_t *self = cstate->tunnel;

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
    http2_server_con_state_t *cstate = (http2_server_con_state_t *)userdata;
    tunnel_t *self = cstate->tunnel;

    http2_server_child_con_state_t *stream =
        nghttp2_session_get_stream_user_data(session, stream_id);
    if (!stream)
        return 0;

    // LOGD("on_data_chunk_recv_callback\n");
    // LOGD("stream_id=%d length=%d\n", stream_id, (int)len);
    //  //LOGD("%.*s\n", (int)len, data);

    if (cstate->content_type == APPLICATION_GRPC)
    {
        // grpc_message_hd
        if (len >= GRPC_MESSAGE_HDLEN)
        {
            grpc_message_hd msghd;
            grpc_message_hd_unpack(&msghd, data);
            // LOGD("grpc_message_hd: flags=%d length=%d\n", msghd.flags, msghd.length);
            data += GRPC_MESSAGE_HDLEN;
            len -= GRPC_MESSAGE_HDLEN;
            // //LOGD("%.*s\n", (int)len, data);
        }
    }

    shift_buffer_t *buf = popBuffer(buffer_pools[cstate->line->tid]);
    shiftl(buf, lCap(buf) / 1.25); // use some unused space
    setLen(buf, len);
    memcpy(rawBuf(buf), data, len);
    context_t *stream_data = newContext(stream->line);
    stream_data->payload = buf;

    stream->tunnel->upStream(stream->tunnel, stream_data);
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

    // LOGD("on_frame_recv_callback\n");
    print_frame_hd(&frame->hd);
    http2_server_con_state_t *cstate = (http2_server_con_state_t *)userdata;
    tunnel_t *self = cstate->tunnel;

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

    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_REQUEST)
    {
        return 0;
    }
    http2_server_child_con_state_t *stream = create_http2_stream(cstate, cstate->line, self->up, frame->hd.stream_id);
    nghttp2_session_set_stream_user_data(session, frame->hd.stream_id,
                                         stream);

    {
        nghttp2_nv nvs[10];
        int nvlen = 0;
        nvs[nvlen++] = make_nv(":status", "200");
        if (cstate->content_type == APPLICATION_GRPC)
        {
            // correct content_type: application/grpc
            nvs[nvlen++] = make_nv("content-type", http_content_type_str(APPLICATION_GRPC));
            nvs[nvlen++] = make_nv("accept-encoding", "identity");
        }

        int flags = NGHTTP2_FLAG_END_HEADERS;

        nghttp2_submit_headers(cstate->session, flags, stream->stream_id, NULL, &nvs[0], nvlen, NULL);
        cstate->state = H2_SEND_HEADERS;
    }
    {
        context_t *init_ctx = newContext(stream->line);
        init_ctx->init = true;
        stream->tunnel->upStream(stream->tunnel, init_ctx);
    }
    return 0;
}

static bool trySendResponse(tunnel_t *self, line_t *line, http2_server_child_con_state_t *stream, shift_buffer_t **buf)
{
    // HTTP2_MAGIC,HTTP2_SETTINGS,HTTP2_HEADERS
    http2_server_con_state_t *cstate = ((http2_server_con_state_t *)(((line->chains_state)[self->chain_index])));
    if (cstate == NULL)
        return false;

    char *data = NULL;
    size_t len;
    len = nghttp2_session_mem_send(cstate->session, (const uint8_t **)&data);
    // LOGD("nghttp2_session_mem_send %d\n", len);
    if (len != 0)
    {
        shift_buffer_t *send_buf = popBuffer(buffer_pools[line->tid]);
        shiftl(send_buf, lCap(send_buf) / 1.25); // use some unused space
        setLen(send_buf, len);
        memcpy(rawBuf(send_buf), data, len);
        context_t *answer = newContext(line);
        answer->payload = send_buf;
        self->dw->downStream(self->dw, answer);

        if (nghttp2_session_want_read(cstate->session) == 0 &&
            nghttp2_session_want_write(cstate->session) == 0)
        {
            if (buf != NULL && *buf != NULL)
            {
                reuseBuffer(buffer_pools[line->tid], *buf);
                *buf = NULL;
            }
            context_t *fin_ctx = newContext(line);
            fin_ctx->fin = true;
            cleanup(cstate);
            self->dw->downStream(self->dw, fin_ctx);
            return false;
        }

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

        // LOGD("HTTP2 SEND_DATA_FRAME_HD...\n");
        if (cstate->content_type == APPLICATION_GRPC)
        {
            grpc_message_hd msghd;
            msghd.flags = 0;
            msghd.length = bufLen(*buf);
            // LOGD("grpc_message_hd: flags=%d length=%d\n", msghd.flags, msghd.length);

            // grpc server send grpc-status in HTTP2 header frame
            flags = HTTP2_FLAG_NONE;

            shiftl(*buf, GRPC_MESSAGE_HDLEN);

            grpc_message_hd_pack(&msghd, rawBuf(*buf));
        }
        http2_frame_hd framehd;

        framehd.length = bufLen(*buf);
        framehd.type = HTTP2_DATA;
        framehd.flags = flags;
        framehd.stream_id = stream->stream_id;
        shiftl(*buf, HTTP2_FRAME_HDLEN);
        http2_frame_hd_pack(&framehd, rawBuf(*buf));
        context_t *answer = newContext(line);
        answer->payload = *buf;
        self->dw->downStream(self->dw, answer);

        goto send_done;
    }
    else if (cstate->state == H2_SEND_DATA)
    {
    send_done:
        *buf = NULL;
        cstate->state = H2_SEND_DONE;
    }

    // LOGD("GetSendData %d\n", len);
    return false;
}

static inline void upStream(tunnel_t *self, context_t *c)
{
    http2_server_state_t *state = STATE(self);
    if (c->payload != NULL)
    {
        http2_server_con_state_t *cstate = CSTATE(c);

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
            //TODO  not http2 -> fallback
            context_t *fail_ctx = newContext(c->line);
            fail_ctx->fin = true;
            cleanup(CSTATE(c));
            destroyContext(c);
            self->dw->downStream(self->dw, fail_ctx);
            return;
        }

        while (trySendResponse(self, c->line, NULL, NULL))
            ;
        destroyContext(c);
    }
    else
    {
        if (c->init)
        {
            CSTATE_MUT(c) = malloc(sizeof(http2_server_con_state_t));
            memset(CSTATE(c), 0, sizeof(http2_server_con_state_t));
            http2_server_con_state_t *cstate = CSTATE(c);
            nghttp2_session_server_new(&cstate->session, state->cbs, cstate);
            cstate->state = H2_WANT_RECV;
            cstate->tunnel = self;
            cstate->line = c->line;

            nghttp2_settings_entry settings[] = {
                {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
            nghttp2_submit_settings(cstate->session, NGHTTP2_FLAG_NONE, settings, ARRAY_SIZE(settings));

            cstate->state = H2_SEND_SETTINGS;
            destroyContext(c);
        }
        else if (c->fin)
        {
            cleanup(CSTATE(c));

            destroyContext(c);
        }
    }
}

static inline void downStream(tunnel_t *self, context_t *c)
{
    http2_server_child_con_state_t *stream = (http2_server_child_con_state_t *)CSTATE(c);
    http2_server_con_state_t *cstate = stream->parent->chains_state[self->chain_index];

    if (c->payload != NULL)
    {

        cstate->state = H2_SEND_HEADERS;

        shift_buffer_t *buf = c->payload;
        c->payload = NULL;
        while (trySendResponse(self, cstate->line, stream, &buf))
            ;
        assert(buf == NULL);
        destroyContext(c);
    }
    else
    {
        if (c->fin)
        {
            int flags = NGHTTP2_FLAG_END_STREAM | NGHTTP2_FLAG_END_HEADERS;
            if (cstate->content_type == APPLICATION_GRPC)
            {
                nghttp2_nv nv = make_nv("grpc-status", "0");
                nghttp2_submit_headers(cstate->session, flags, stream->stream_id, NULL, &nv, 1, NULL);
            }
            else
                nghttp2_submit_headers(cstate->session, flags, stream->stream_id, NULL, NULL, 0, NULL);
            while (trySendResponse(self, cstate->line, stream, NULL))
                ;

            remove_stream(cstate, stream);
            delete_http2_stream(stream);
            if (nghttp2_session_want_read(cstate->session) == 0 &&
                nghttp2_session_want_write(cstate->session) == 0)
            {
                context_t *fin_ctx = newContext(stream->parent);
                fin_ctx->fin = true;
                cleanup(cstate);
                self->dw->downStream(self->dw, fin_ctx);
            }

            destroyContext(c);
            return;
        }
        context_t *main_line_ctx = newContext(stream->parent);
        *main_line_ctx = *c;
        main_line_ctx->line = stream->parent;
        destroyContext(c);
        self->dw->downStream(self->dw, main_line_ctx);
    }
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
    nghttp2_session_callbacks_set_on_header_callback(state->cbs, on_header_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(state->cbs, on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(state->cbs, on_frame_recv_callback);

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
