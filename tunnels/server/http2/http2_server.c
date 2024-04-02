#include "http2_server.h"

#include "types.h"
#include "helpers.h"
#include "loggers/network_logger.h"

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

    http2_server_con_state_t *con = (http2_server_con_state_t *)userdata;
    tunnel_t *self = con->tunnel;

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
            con->content_type = http_content_type_enum(value);
        }
    }

    return 0;
}

static int on_data_chunk_recv_callback(nghttp2_session *session,
                                       uint8_t flags, int32_t stream_id, const uint8_t *data,
                                       size_t len, void *userdata)
{
    if (userdata == NULL || len <= 0)
        return 0;
    http2_server_con_state_t *con = (http2_server_con_state_t *)userdata;
    tunnel_t *self = con->tunnel;

    http2_server_child_con_state_t *stream =
        nghttp2_session_get_stream_user_data(session, stream_id);
    if (!stream)
        return 0;

    // LOGD("on_data_chunk_recv_callback\n");
    // LOGD("stream_id=%d length=%d\n", stream_id, (int)len);
    // LOGD("up: %d\n", (int)len);

    if (con->content_type == APPLICATION_GRPC)
    {

        shift_buffer_t *buf = popBuffer(buffer_pools[con->line->tid]);
        shiftl(buf, lCap(buf) / 1.25); // use some unused space
        setLen(buf, len);
        memcpy(rawBuf(buf), data, len);
        bufferStreamPush(stream->chunkbs, buf);

        while (true)
        {
            if (stream->bytes_needed == 0 && bufferStreamLen(stream->chunkbs) >= GRPC_MESSAGE_HDLEN)
            {
                shift_buffer_t *gheader_buf = bufferStreamRead(stream->chunkbs, GRPC_MESSAGE_HDLEN);
                grpc_message_hd msghd;
                grpc_message_hd_unpack(&msghd, rawBuf(gheader_buf));
                stream->bytes_needed = msghd.length;
                reuseBuffer(buffer_pools[con->line->tid], gheader_buf);
            }
            if (stream->bytes_needed > 0 && bufferStreamLen(stream->chunkbs) >= stream->bytes_needed)
            {
                shift_buffer_t *gdata_buf = bufferStreamRead(stream->chunkbs, stream->bytes_needed);
                stream->bytes_needed = 0;
                context_t *stream_data = newContext(stream->line);
                stream_data->payload = gdata_buf;
                stream_data->src_io = con->io;
                if (!stream->first_sent)
                {
                    stream->first_sent = true;
                    stream_data->first = true;
                }
                stream->tunnel->upStream(stream->tunnel, stream_data);

                if (nghttp2_session_get_stream_user_data(session, stream_id))
                    continue;
            }
            break;
        }
    }
    else
    {
        shift_buffer_t *buf = popBuffer(buffer_pools[con->line->tid]);
        shiftl(buf, lCap(buf) / 1.25); // use some unused space
        setLen(buf, len);
        memcpy(rawBuf(buf), data, len);
        context_t *stream_data = newContext(stream->line);
        stream_data->payload = buf;
        stream_data->src_io = con->io;
        if (!stream->first_sent)
        {
            stream->first_sent = true;
            stream_data->first = true;
        }
        stream->tunnel->upStream(stream->tunnel, stream_data);
    }

    return 0;
}

static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *userdata)
{
    if (userdata == NULL)
        return 0;

    // LOGD("on_frame_recv_callback\n");
    print_frame_hd(&frame->hd);
    http2_server_con_state_t *con = (http2_server_con_state_t *)userdata;
    tunnel_t *self = con->tunnel;

    switch (frame->hd.type)
    {
    case NGHTTP2_DATA:
        con->state = H2_RECV_DATA;
        break;
    case NGHTTP2_HEADERS:
        con->state = H2_RECV_HEADERS;
        break;
    case NGHTTP2_SETTINGS:
        con->state = H2_RECV_SETTINGS;
        break;
    case NGHTTP2_PING:
        con->state = H2_RECV_PING;
        break;
    case NGHTTP2_RST_STREAM:
    case NGHTTP2_WINDOW_UPDATE:
        // ignore
        return 0;
    default:
        break;
    }
    // if (con->state == H2_RECV_HEADERS && con->parsed->http_cb)
    // {
    //     con->parsed->http_cb(con->parsed, HP_HEADERS_COMPLETE, NULL, 0);
    // }

    if ((frame->hd.flags & HTTP2_FLAG_END_STREAM) == HTTP2_FLAG_END_STREAM)
    {
        http2_server_child_con_state_t *stream =
            nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
        if (!stream)
            return 0;
        nghttp2_session_set_stream_user_data(con->session, stream->stream_id, NULL);
        context_t *fc = newFinContext(stream->line);
        tunnel_t *dest = stream->tunnel;
        remove_stream(con, stream);
        delete_http2_stream(stream);
        CSTATE_MUT(fc) = NULL;

        dest->upStream(dest, fc);
        return 0;
    }

    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_REQUEST)
    {
        return 0;
    }

    nghttp2_nv nvs[10];
    int nvlen = 0;
    nvs[nvlen++] = make_nv(":status", "200");
    if (con->content_type == APPLICATION_GRPC)
    {
        // correct content_type: application/grpc
        nvs[nvlen++] = make_nv("content-type", http_content_type_str(APPLICATION_GRPC));
        nvs[nvlen++] = make_nv("accept-encoding", "identity");
    }

    int flags = NGHTTP2_FLAG_END_HEADERS;

    nghttp2_submit_headers(con->session, flags, frame->hd.stream_id, NULL, &nvs[0], nvlen, NULL);
    con->state = H2_SEND_HEADERS;

    http2_server_child_con_state_t *stream = create_http2_stream(con, con->line, self->up, frame->hd.stream_id);
    add_stream(con, stream);
    stream->tunnel->upStream(stream->tunnel, newInitContext(stream->line));

    return 0;
}

static bool trySendResponse(tunnel_t *self, http2_server_con_state_t *con, size_t stream_id, hio_t *stream_io, shift_buffer_t *buf)
{
    line_t *line = con->line;
    // http2_server_con_state_t *con = ((http2_server_con_state_t *)(((line->chains_state)[self->chain_index])));
    if (con == NULL)
        return false;

    char *data = NULL;
    size_t len;
    len = nghttp2_session_mem_send(con->session, (const uint8_t **)&data);
    // LOGD("nghttp2_session_mem_send %d\n", len);
    if (len > 0)
    {
        shift_buffer_t *send_buf = popBuffer(buffer_pools[line->tid]);
        shiftl(send_buf, lCap(send_buf) / 1.25); // use some unused space
        setLen(send_buf, len);
        memcpy(rawBuf(send_buf), data, len);
        context_t *response_data = newContext(line);
        response_data->payload = send_buf;
        response_data->src_io = stream_io;
        self->dw->downStream(self->dw, response_data);

        // if (nghttp2_session_want_read(con->session) == 0 &&
        //     nghttp2_session_want_write(con->session) == 0)
        // {
        //     if (buf != NULL)
        //     {
        //         reuseBuffer(buffer_pools[line->tid], buf);
        //     }
        //     context_t *fin_ctx = newFinContext(line);
        //     delete_http2_connection(con);
        //     self->dw->downStream(self->dw, fin_ctx);
        //     return false;
        // }

        return true;
    }
    if (buf == NULL || bufLen(buf) <= 0)
        return false;

    // HTTP2_DATA
    if (con->state == H2_SEND_HEADERS)
    {

        // http2_flag flags = HTTP2_FLAG_END_STREAM;
        http2_flag flags = HTTP2_FLAG_NONE;

        // HTTP2 DATA framehd
        con->state = H2_SEND_DATA;

        // LOGD("HTTP2 SEND_DATA_FRAME_HD...\n");
        if (con->content_type == APPLICATION_GRPC)
        {
            grpc_message_hd msghd;
            msghd.flags = 0;
            msghd.length = bufLen(buf);
            // LOGD("grpc_message_hd: flags=%d length=%d\n", msghd.flags, msghd.length);

            // grpc server send grpc-status in HTTP2 header frame
            flags = HTTP2_FLAG_NONE;

            shiftl(buf, GRPC_MESSAGE_HDLEN);

            grpc_message_hd_pack(&msghd, rawBuf(buf));
        }

        http2_frame_hd framehd;
        framehd.length = bufLen(buf);
        framehd.type = HTTP2_DATA;
        framehd.flags = flags;
        framehd.stream_id = stream_id;
        shiftl(buf, HTTP2_FRAME_HDLEN);
        http2_frame_hd_pack(&framehd, rawBuf(buf));
        context_t *response_data = newContext(line);
        response_data->payload = buf;
        response_data->src_io = stream_io;
        self->dw->downStream(self->dw, response_data);

        goto send_done;
    }
    else if (con->state == H2_SEND_DATA)
    {
    send_done:;
        con->state = H2_SEND_DONE;
    }

    // LOGD("GetSendData %d\n", len);
    return false;
}

static inline void upStream(tunnel_t *self, context_t *c)
{
    http2_server_state_t *state = STATE(self);
    if (c->payload != NULL)
    {
        http2_server_con_state_t *con = CSTATE(c);
        con->io = c->src_io;
        con->state = H2_WANT_RECV;
        size_t len = bufLen(c->payload);
        size_t ret = nghttp2_session_mem_recv2(con->session, (const uint8_t *)rawBuf(c->payload), len);
        DISCARD_CONTEXT(c);

        if (!ISALIVE(c))
        {
            destroyContext(c);
            return;
        }

        assert(ret == len);
        // {
        //     // TODO  not http2 -> fallback
        //     context_t *fin_ctx = newFinContext(con->line);
        //     delete_http2_connection(CSTATE(c));
        //     destroyContext(c);
        //     self->dw->downStream(self->dw, fin_ctx);

        //     return;
        // }

        while (trySendResponse(self, con, 0, NULL, NULL))
            if (!ISALIVE(c))
            {
                destroyContext(c);
                return;
            }
        destroyContext(c);
    }
    else
    {
        if (c->init)
        {
            CSTATE_MUT(c) = create_http2_connection(self, c->line, c->src_io);
            self->dw->downStream(self->dw, newEstContext(c->line));

            destroyContext(c);
        }
        else if (c->fin)
        {
            delete_http2_connection(CSTATE(c));
            destroyContext(c);
        }
    }
}

static inline void downStream(tunnel_t *self, context_t *c)
{
    http2_server_child_con_state_t *stream = (http2_server_child_con_state_t *)CSTATE(c);
    http2_server_con_state_t *con = stream->parent->chains_state[self->chain_index];
    stream->io = c->src_io ? c->src_io : stream->io;

    if (c->payload != NULL)
    {
        con->state = H2_SEND_HEADERS;
        while (trySendResponse(self, con, stream->stream_id, stream->io, c->payload))
            if (!ISALIVE(c))
            {
                destroyContext(c);
                return;
            }
        c->payload = NULL;
        destroyContext(c);
    }
    else
    {
        if (c->fin)
        {
            int flags = NGHTTP2_FLAG_END_STREAM | NGHTTP2_FLAG_END_HEADERS;
            if (con->content_type == APPLICATION_GRPC)
            {
                nghttp2_nv nv = make_nv("grpc-status", "0");
                nghttp2_submit_headers(con->session, flags, stream->stream_id, NULL, &nv, 1, NULL);
            }
            else
                nghttp2_submit_headers(con->session, flags, stream->stream_id, NULL, NULL, 0, NULL);

            nghttp2_session_set_stream_user_data(con->session, stream->stream_id, NULL);
            remove_stream(con, stream);
            delete_http2_stream(stream);
            CSTATE_MUT(c) = NULL;

            while (trySendResponse(self, con, 0, NULL, NULL))
                if (!ISALIVE(c))
                {
                    destroyContext(c);
                    return;
                }

            if (nghttp2_session_want_read(con->session) == 0 &&
                nghttp2_session_want_write(con->session) == 0)
            {
                context_t *fin_ctx = newFinContext(con->line);
                delete_http2_connection(con);
                self->dw->downStream(self->dw, fin_ctx);
            }

            destroyContext(c);
            return;
        }
        else
            destroyContext(c);
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

    nghttp2_option_new(&(state->ngoptions));
    nghttp2_option_set_peer_max_concurrent_streams(state->ngoptions, 0xffffffffu);
    nghttp2_option_set_no_closed_streams(state->ngoptions, 1);

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
