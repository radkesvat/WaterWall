#include "http2_client.h"
#include "types.h"
#include "helpers.h"

#define MAX_CHUNK_SIZE 8100

static void sendGrpcFinalData(tunnel_t *self, line_t *line, size_t stream_id)
{
    http2_frame_hd framehd;
    shift_buffer_t *buf = popBuffer(buffer_pools[line->tid]);
    setLen(buf, HTTP2_FRAME_HDLEN);

    framehd.length = 0;
    framehd.type = HTTP2_DATA;
    framehd.flags = HTTP2_FLAG_END_STREAM;
    framehd.stream_id = stream_id;
    http2_frame_hd_pack(&framehd, rawBuf(buf));
    context_t *endstream_ctx = newContext(line);
    endstream_ctx->payload = buf;
    self->up->upStream(self->up, endstream_ctx);
}
static bool trySendRequest(tunnel_t *self, http2_client_con_state_t *con, size_t stream_id, hio_t *stream_io, shift_buffer_t *buf)
{
    line_t *line = con->line;
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
        context_t *req = newContext(line);
        req->payload = send_buf;
        req->src_io = stream_io;
        if (!con->first_sent)
        {
            con->first_sent = true;
            req->first = true;
        }
        self->up->upStream(self->up, req);

        // if (nghttp2_session_want_read(con->session) == 0 &&
        //     nghttp2_session_want_write(con->session) == 0)
        // {
        //     if (buf != NULL)
        //     {
        //         reuseBuffer(buffer_pools[line->tid], buf);
        //         buf = NULL;
        //     }
        //     context_t *fin_ctx = newFinContext(line);
        //     delete_http2_connection(con);
        //     con->tunnel->up->upStream(con->tunnel->up, fin_ctx);
        //     return false;
        // }

        return true;
    }
    assert(len >= 0);

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
        context_t *req = newContext(line);
        req->payload = buf;
        req->src_io = stream_io;
        self->up->upStream(self->up, req);

        goto send_done;
    }
    else if (con->state == H2_SEND_DATA)
    {
    send_done:
        con->state = H2_SEND_DONE;
    }

    // LOGD("GetSendData %d\n", len);
    return false;
}
static void flush_write_queue(http2_client_con_state_t *con)
{
    tunnel_t *self = con->tunnel;
    context_t *g = newContext(con->line); // keep the line alive
    while (contextQueueLen(con->queue) > 0)
    {
        context_t *stream_context = contextQueuePop(con->queue);
        http2_client_child_con_state_t *stream = CSTATE(stream_context);
        stream->io = stream_context->src_io;
        con->state = H2_SEND_HEADERS;

        // consumes payload
        while (trySendRequest(self, con, stream->stream_id, stream->io, stream_context->payload))
        {
            if (!ISALIVE(g))
            {
                destroyContext(g);
                return;
            }
        }
    }
    destroyContext(g);
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

    http2_client_con_state_t *con = (http2_client_con_state_t *)userdata;
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

    return 0;
}

static int on_data_chunk_recv_callback(nghttp2_session *session,
                                       uint8_t flags, int32_t stream_id, const uint8_t *data,
                                       size_t len, void *userdata)
{
    if (userdata == NULL || len <= 0)
        return 0;
    http2_client_con_state_t *con = (http2_client_con_state_t *)userdata;
    tunnel_t *self = con->tunnel;

    http2_client_child_con_state_t *stream =
        nghttp2_session_get_stream_user_data(session, stream_id);
    if (!stream)
        return 0;
    // LOGD("on_data_chunk_recv_callback\n");
    // LOGD("stream_id=%d length=%d\n", stream_id, (int)len);
    // LOGD("down: %d\n", (int)len);

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
                stream->tunnel->downStream(stream->tunnel, stream_data);
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
        stream->tunnel->downStream(stream->tunnel, stream_data);
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
    http2_client_con_state_t *con = (http2_client_con_state_t *)userdata;
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
    if ((frame->hd.flags & HTTP2_FLAG_END_STREAM) == HTTP2_FLAG_END_STREAM)
    {
        http2_client_child_con_state_t *stream =
            nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
        if (!stream)
            return 0;
        nghttp2_session_set_stream_user_data(con->session, stream->stream_id, NULL);
        context_t *fc = newFinContext(stream->line);
        tunnel_t *dest = stream->tunnel;
        remove_stream(con, stream);
        delete_http2_stream(stream);
        CSTATE_MUT(fc) = NULL;

        dest->downStream(dest, fc);

        return 0;
    }

    if ((frame->hd.type & NGHTTP2_HEADERS) == NGHTTP2_HEADERS)
    {
        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE)
        {
            http2_client_child_con_state_t *stream = nghttp2_session_get_stream_user_data(con->session, frame->hd.stream_id);
            con->handshake_completed = true;
            flush_write_queue(con);
            stream->tunnel->downStream(stream->tunnel, newEstContext(stream->line));
        }
    }

    return 0;
}

static inline void upStream(tunnel_t *self, context_t *c)
{
    http2_client_state_t *state = STATE(self);
    if (c->payload != NULL)
    {
        http2_client_child_con_state_t *stream = CSTATE(c);
        http2_client_con_state_t *con = stream->parent->chains_state[self->chain_index];
        stream->io = c->src_io;
        if (!con->handshake_completed)
        {
            contextQueuePush(con->queue, c);
            return;
        }

        con->state = H2_SEND_HEADERS;

        // consumes payload
        while (trySendRequest(self, con, stream->stream_id, stream->io, c->payload))
            ;
        c->payload = NULL;
        destroyContext(c);
    }
    else
    {
        if (c->init)
        {
            http2_client_con_state_t *con = take_http2_connection(self, c->line->tid, NULL);
            http2_client_child_con_state_t *stream = create_http2_stream(con, c->line, c->src_io);
            CSTATE_MUT(c) = stream;
            nghttp2_session_set_stream_user_data(con->session, stream->stream_id, stream);

            if (!con->init_sent)
            {
                con->init_sent = true;
                self->up->upStream(self->up, newInitContext(con->line));
                if (!ISALIVE(c))
                {
                    destroyContext(c);
                    return;
                }
            }

            while (trySendRequest(self, con, 0, NULL, NULL))
                if (!ISALIVE(c))
                {
                    destroyContext(c);
                    return;
                }

            destroyContext(c);
        }
        else if (c->fin)
        {
            http2_client_child_con_state_t *stream = CSTATE(c);
            http2_client_con_state_t *con = stream->parent->chains_state[self->chain_index];
            if (con->content_type == APPLICATION_GRPC)
            {
                sendGrpcFinalData(self, con->line, stream->stream_id);
            }

            nghttp2_session_set_stream_user_data(con->session, stream->stream_id, NULL);
            remove_stream(con, stream);
            if (con->root.next == NULL && ISALIVE(c))
            {
                context_t *con_fc = newFinContext(con->line);
                tunnel_t *con_dest = con->tunnel->up;
                delete_http2_connection(con);
                con_dest->upStream(con_dest, con_fc);
            }
            delete_http2_stream(stream);
            CSTATE_MUT(c) = NULL;

            destroyContext(c);
            return;
        }
    }
}

static inline void downStream(tunnel_t *self, context_t *c)
{
    http2_client_state_t *state = STATE(self);
    http2_client_con_state_t *con = CSTATE(c);
    con->io = c->src_io;

    if (c->payload != NULL)
    {

        con->state = H2_WANT_RECV;
        size_t len = bufLen(c->payload);
        size_t ret = nghttp2_session_mem_recv2(con->session, (const uint8_t *)rawBuf(c->payload), len);
        assert(ret == len);
        DISCARD_CONTEXT(c);

        if (!ISALIVE(c))
        {
            destroyContext(c);
            return;
        }
        while (trySendRequest(self, con, 0, NULL, NULL))
            if (!ISALIVE(c))
            {
                destroyContext(c);
                return;
            }

        if (con->root.next == NULL)
        {
            context_t *con_fc = newFinContext(con->line);
            tunnel_t *con_dest = con->tunnel->up;
            delete_http2_connection(con);
            con_dest->upStream(con_dest, con_fc);
        }
        // if (con->childs_added >= MAX_CHILD_PER_STREAM && con->root.next == NULL && ISALIVE(c))
        // {
        //     context_t *fin_ctx = newFinContext(con->line);
        //     delete_http2_connection(con);
        //     con->tunnel->up->upStream(con->tunnel->up, fin_ctx);
        // }

        if (!ISALIVE(c))
        {
            destroyContext(c);
            return;
        }

        // {
        //     context_t *fin_ctx = newFinContext(con->line);
        //     delete_http2_connection(con);
        //     con->tunnel->upStream(con->tunnel, fin_ctx);
        // }
        destroyContext(c);
    }
    else
    {

        if (c->fin)
        {
            delete_http2_connection(con);
        }

        destroyContext(c);
    }
}

static void http2ClientUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void http2ClientPacketUpStream(tunnel_t *self, context_t *c)
{
    LOGF("Http2Client: Http2 protocol dose not run on udp");
    exit(1);
}
static void http2ClientDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}
static void http2ClientPacketDownStream(tunnel_t *self, context_t *c)
{
    LOGF("Http2Client: Http2 protocol dose not run on udp");
    exit(1);
}

tunnel_t *newHttp2Client(node_instance_context_t *instance_info)
{
    http2_client_state_t *state = malloc(sizeof(http2_client_state_t) + (threads_count * sizeof(thread_connection_pool_t)));
    memset(state, 0, sizeof(http2_client_state_t));
    cJSON *settings = instance_info->node_settings_json;

    nghttp2_session_callbacks_new(&(state->cbs));
    nghttp2_session_callbacks_set_on_header_callback(state->cbs, on_header_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(state->cbs, on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(state->cbs, on_frame_recv_callback);

    for (size_t i = 0; i < threads_count; i++)
    {
        state->thread_cpool[i] = (thread_connection_pool_t){.round_index = 0, .cons = vec_cons_with_capacity(8)};
    }

    if (!getStringFromJsonObject(&(state->host), settings, "host"))
    {
        LOGF("JSON Error: Http2Client->settings->host (string field) : The data was empty or invalid.");
        return NULL;
    }
    getStringFromJsonObjectOrDefault(&(state->path), settings, "path", "/");

    if (!getIntFromJsonObject(&(state->host_port), settings, "port"))
    {
        LOGF("JSON Error: Http2Client->settings->port (number field) : The data was empty or invalid.");
        return NULL;
    }

    getStringFromJsonObjectOrDefault(&(state->scheme), settings, "scheme", "https");

    char *content_type_buf = NULL;
    if (getStringFromJsonObject(&content_type_buf, settings, "content-type"))
    {
        state->content_type = http_content_type_enum(content_type_buf);
        free(content_type_buf);
    }

    nghttp2_option_new(&(state->ngoptions));
    nghttp2_option_set_peer_max_concurrent_streams(state->ngoptions, 0xffffffffu);
    nghttp2_option_set_no_closed_streams(state->ngoptions, 1);
    // nghttp2_option_set_no_http_messaging use this with grpc?

    tunnel_t *t = newTunnel();
    t->state = state;
    t->upStream = &http2ClientUpStream;
    t->packetUpStream = &http2ClientPacketUpStream;
    t->downStream = &http2ClientDownStream;
    t->packetDownStream = &http2ClientPacketDownStream;

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
