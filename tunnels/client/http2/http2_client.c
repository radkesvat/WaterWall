#include "http2_client.h"
#include "helpers.h"
#include "types.h"
#include "utils/jsonutils.h"

enum
{
    kDefaultConcurrency = 50 // 50 cons will be muxed into 1
};

static void sendGrpcFinalData(tunnel_t *self, line_t *line, size_t stream_id)
{
    http2_frame_hd  framehd;
    shift_buffer_t *buf = popBuffer(getLineBufferPool(line));
    setLen(buf, HTTP2_FRAME_HDLEN);

    framehd.length    = 0;
    framehd.type      = kHttP2Data;
    framehd.flags     = kHttP2FlagEndStream;
    framehd.stream_id = stream_id;
    http2FrameHdPack(&framehd, rawBufMut(buf));
    context_t *endstream_ctx = newContext(line);
    endstream_ctx->payload   = buf;
    self->up->upStream(self->up, endstream_ctx);
}
static bool trySendRequest(tunnel_t *self, http2_client_con_state_t *con, size_t stream_id, hio_t *stream_io,
                           shift_buffer_t *buf)
{
    line_t *line = con->line;
    if (con == NULL)
    {
        return false;
    }

    char  *data = NULL;
    size_t len;
    len = nghttp2_session_mem_send(con->session, (const uint8_t **) &data);
    // LOGD("nghttp2_session_mem_send %d\n", len);
    if (len > 0)
    {
        shift_buffer_t *send_buf = popBuffer(getLineBufferPool(line));
        shiftl(send_buf, lCap(send_buf) / 2); // use some unused space
        setLen(send_buf, len);
        writeRaw(send_buf, data, len);

        context_t *req = newContext(line);
        req->payload   = send_buf;
        req->src_io    = stream_io;
        if (! con->first_sent)
        {
            con->first_sent = true;
            req->first      = true;
        }
        self->up->upStream(self->up, req);

        return true;
    }
    assert(len >= 0);

    if (buf == NULL || bufLen(buf) <= 0)
    {
        return false;
    }
    // HTTP2_DATA
    if (con->state == kH2SendHeaders)
    {

        // http2_flag flags = HTTP2_FLAG_END_STREAM;
        http2_flag flags = kHttP2FlagNone;

        // HTTP2 DATA framehd
        con->state = kH2SendData;

        // LOGD("HTTP2 SEND_DATA_FRAME_HD...\n");
        if (con->content_type == kApplicationGrpc)
        {
            grpc_message_hd msghd;
            msghd.flags  = 0;
            msghd.length = bufLen(buf);
            // LOGD("grpc_message_hd: flags=%d length=%d\n", msghd.flags, msghd.length);

            // grpc server send grpc-status in HTTP2 header frame
            flags = kHttP2FlagNone;

            shiftl(buf, GRPC_MESSAGE_HDLEN);

            grpcMessageHdPack(&msghd, rawBufMut(buf));
        }
        http2_frame_hd framehd;

        framehd.length    = bufLen(buf);
        framehd.type      = kHttP2Data;
        framehd.flags     = flags;
        framehd.stream_id = stream_id;
        shiftl(buf, HTTP2_FRAME_HDLEN);
        http2FrameHdPack(&framehd, rawBufMut(buf));
        context_t *req = newContext(line);
        req->payload   = buf;
        req->src_io    = stream_io;
        self->up->upStream(self->up, req);

        goto send_done;
    }
    else if (con->state == kH2SendData)
    {
    send_done:;
        con->state = kH2SendDone;
    }

    // LOGD("GetSendData %d\n", len);
    return false;
}
static void flushWriteQueue(http2_client_con_state_t *con)
{
    tunnel_t  *self = con->tunnel;
    context_t *g    = newContext(con->line); // keep the line alive
    while (contextQueueLen(con->queue) > 0)
    {
        context_t                      *stream_context = contextQueuePop(con->queue);
        http2_client_child_con_state_t *stream         = CSTATE(stream_context);
        stream->io                                     = stream_context->src_io;
        con->state                                     = kH2SendHeaders;

        // consumes payload
        while (trySendRequest(self, con, stream->stream_id, stream->io, stream_context->payload))
        {
            if (! isAlive(g->line))
            {
                destroyContext(g);
                return;
            }
        }
    }
    destroyContext(g);
}

static int onHeaderCallback(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *_name, size_t namelen,
                            const uint8_t *_value, size_t valuelen, uint8_t flags, void *userdata)
{
    (void) session;
    (void) namelen;
    (void) valuelen;
    (void) flags;
    if (userdata == NULL)
    {
        return 0;
    }

    // LOGD("onHeaderCallback\n");
    printFrameHd(&frame->hd);
    const char *name  = (const char *) _name;
    const char *value = (const char *) _value;
    // LOGD("%s: %s\n", name, value);

    http2_client_con_state_t *con  = (http2_client_con_state_t *) userdata;
    tunnel_t                 *self = con->tunnel;

    // Todo (http headers) should be saved somewhere
    // if (*name == ':')
    // {
    //     if (strcmp(name, ":method") == 0)
    //     {
    //         // req->method = http_method_enum(value);
    //     }
    //     else if (strcmp(name, ":path") == 0)
    //     {
    //         // req->url = value;
    //     }
    //     else if (strcmp(name, ":scheme") == 0)
    //     {
    //         // req->headers["Scheme"] = value;
    //     }
    //     else if (strcmp(name, ":authority") == 0)
    //     {
    //         // req->headers["Host"] = value;
    //     }
    // }

    return 0;
}

static int onDataChunkRecvCallback(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data,
                                   size_t len, void *userdata)
{
    (void) flags;
    if (userdata == NULL || len <= 0)
    {
        return 0;
    }
    http2_client_con_state_t *con  = (http2_client_con_state_t *) userdata;
    tunnel_t                 *self = con->tunnel;

    http2_client_child_con_state_t *stream = nghttp2_session_get_stream_user_data(session, stream_id);
    if (! stream)
    {
        return 0;
    }
    // LOGD("onDataChunkRecvCallback\n");
    // LOGD("stream_id=%d length=%d\n", stream_id, (int)len);
    // LOGD("down: %d\n", (int)len);

    if (con->content_type == kApplicationGrpc)
    {

        shift_buffer_t *buf = popBuffer(getLineBufferPool(con->line));
        shiftl(buf, lCap(buf) / 2); // use some unused space
        setLen(buf, len);
        writeRaw(buf, data, len);
        bufferStreamPush(stream->chunkbs, buf);

        while (true)
        {
            if (stream->bytes_needed == 0 && bufferStreamLen(stream->chunkbs) >= GRPC_MESSAGE_HDLEN)
            {
                shift_buffer_t *gheader_buf = bufferStreamRead(stream->chunkbs, GRPC_MESSAGE_HDLEN);
                grpc_message_hd msghd;
                grpcMessageHdUnpack(&msghd, rawBuf(gheader_buf));
                stream->bytes_needed = msghd.length;
                reuseBuffer(getLineBufferPool(con->line), gheader_buf);
            }
            if (stream->bytes_needed > 0 && bufferStreamLen(stream->chunkbs) >= stream->bytes_needed)
            {
                shift_buffer_t *gdata_buf = bufferStreamRead(stream->chunkbs, stream->bytes_needed);
                stream->bytes_needed      = 0;
                context_t *stream_data    = newContext(stream->line);
                stream_data->payload      = gdata_buf;
                stream_data->src_io       = con->io;
                stream->tunnel->downStream(stream->tunnel, stream_data);

                if (nghttp2_session_get_stream_user_data(session, stream_id))
                {
                    continue;
                }
            }
            break;
        }
    }
    else
    {
        shift_buffer_t *buf = popBuffer(getLineBufferPool(con->line));
        shiftl(buf, lCap(buf) / 2); // use some unused space
        setLen(buf, len);
        writeRaw(buf, data, len);
        context_t *stream_data = newContext(stream->line);
        stream_data->payload   = buf;
        stream_data->src_io    = con->io;
        stream->tunnel->downStream(stream->tunnel, stream_data);
    }

    return 0;
}

static int onFrameRecvCallback(nghttp2_session *session, const nghttp2_frame *frame, void *userdata)
{
    if (userdata == NULL)
    {
        return 0;
    }

    // LOGD("onFrameRecvCallback\n");
    printFrameHd(&frame->hd);
    http2_client_con_state_t *con  = (http2_client_con_state_t *) userdata;
    tunnel_t                 *self = con->tunnel;

    switch (frame->hd.type)
    {
    case NGHTTP2_DATA:
        con->state = kH2RecvData;
        break;
    case NGHTTP2_HEADERS:
        con->state = kH2RecvHeaders;
        break;
    case NGHTTP2_SETTINGS:
        con->state = kH2RecvSettings;
        break;
    case NGHTTP2_PING:
        // LOGW("Http2Client: GOT PING");
        con->no_ping_ack = false;
        con->state       = kH2RecvPing;
        break;
    case NGHTTP2_RST_STREAM:
    case NGHTTP2_WINDOW_UPDATE:
        // ignore
        return 0;
    default:
        break;
    }
    if (frame->hd.flags & kHttP2FlagEndStream)
    {
        http2_client_child_con_state_t *stream = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
        if (! stream)
        {
            return 0;
        }
        nghttp2_session_set_stream_user_data(con->session, stream->stream_id, NULL);
        context_t *fc   = newFinContext(stream->line);
        tunnel_t  *dest = stream->tunnel;
        removeStream(con, stream);
        deleteHttp2Stream(stream);
        CSTATE_MUT(fc) = NULL;

        dest->downStream(dest, fc);

        return 0;
    }

    if ((frame->hd.type & NGHTTP2_HEADERS) == NGHTTP2_HEADERS)
    {
        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE)
        {
            http2_client_child_con_state_t *stream =
                nghttp2_session_get_stream_user_data(con->session, frame->hd.stream_id);
            con->handshake_completed = true;
            flushWriteQueue(con);
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
        http2_client_con_state_t       *con    = stream->parent->chains_state[self->chain_index];
        stream->io                             = c->src_io;

        if (! con->handshake_completed)
        {
            contextQueuePush(con->queue, c);
            return;
        }

        con->state = kH2SendHeaders;
        // consumes payload
        while (trySendRequest(self, con, stream->stream_id, stream->io, c->payload))
        {
            if (! isAlive(c->line))
            {
                destroyContext(c);
                return;
            }
        }
        c->payload = NULL;
        destroyContext(c);
    }
    else
    {
        if (c->init)
        {
            http2_client_con_state_t       *con    = takeHttp2Connection(self, c->line->tid, NULL);
            http2_client_child_con_state_t *stream = createHttp2Stream(con, c->line, c->src_io);
            CSTATE_MUT(c)                          = stream;
            nghttp2_session_set_stream_user_data(con->session, stream->stream_id, stream);

            if (! con->init_sent)
            {
                con->init_sent = true;
                self->up->upStream(self->up, newInitContext(con->line));
                if (! isAlive(c->line))
                {
                    destroyContext(c);
                    return;
                }
            }

            while (trySendRequest(self, con, 0, NULL, NULL))
            {
                if (! isAlive(c->line))
                {
                    destroyContext(c);
                    return;
                }
            }
            destroyContext(c);
        }
        else if (c->fin)
        {
            http2_client_child_con_state_t *stream = CSTATE(c);
            http2_client_con_state_t       *con    = stream->parent->chains_state[self->chain_index];
            if (con->content_type == kApplicationGrpc)
            {
                sendGrpcFinalData(self, con->line, stream->stream_id);
            }

            nghttp2_session_set_stream_user_data(con->session, stream->stream_id, NULL);
            removeStream(con, stream);
            if (con->root.next == NULL && con->childs_added >= state->concurrency && isAlive(c->line))
            {
                context_t *con_fc   = newFinContext(con->line);
                tunnel_t  *con_dest = con->tunnel->up;
                deleteHttp2Connection(con);
                con_dest->upStream(con_dest, con_fc);
            }
            deleteHttp2Stream(stream);
            CSTATE_MUT(c) = NULL;

            destroyContext(c);
            return;
        }
    }
}

static inline void downStream(tunnel_t *self, context_t *c)
{
    http2_client_state_t     *state = STATE(self);
    http2_client_con_state_t *con   = CSTATE(c);
    con->io                         = c->src_io;

    if (c->payload != NULL)
    {

        con->state = kH2WantRecv;
        size_t len = bufLen(c->payload);
        size_t ret = nghttp2_session_mem_recv2(con->session, (const uint8_t *) rawBuf(c->payload), len);
        assert(ret == len);
        reuseContextBuffer(c);

        if (! isAlive(c->line))
        {
            destroyContext(c);
            return;
        }

        if (ret != len)
        {
            deleteHttp2Connection(con);
            self->dw->downStream(self->dw, newFinContext(c->line));
            destroyContext(c);
            return;
        }

        while (trySendRequest(self, con, 0, NULL, NULL))
        {
            if (! isAlive(c->line))
            {
                destroyContext(c);
                return;
            }
        }

        if (con->root.next == NULL && con->childs_added >= state->concurrency && isAlive(c->line))
        {
            context_t *con_fc   = newFinContext(con->line);
            tunnel_t  *con_dest = con->tunnel->up;
            deleteHttp2Connection(con);
            con_dest->upStream(con_dest, con_fc);
        }

        destroyContext(c);
    }
    else
    {

        if (c->fin)
        {
            deleteHttp2Connection(con);
        }

        destroyContext(c);
    }
}

tunnel_t *newHttp2Client(node_instance_context_t *instance_info)
{
    http2_client_state_t *state =
        malloc(sizeof(http2_client_state_t) + (workers_count * sizeof(thread_connection_pool_t)));
    memset(state, 0, sizeof(http2_client_state_t));
    cJSON *settings = instance_info->node_settings_json;

    nghttp2_session_callbacks_new(&(state->cbs));
    nghttp2_session_callbacks_set_on_header_callback(state->cbs, onHeaderCallback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(state->cbs, onDataChunkRecvCallback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(state->cbs, onFrameRecvCallback);

    for (size_t i = 0; i < workers_count; i++)
    {
        state->thread_cpool[i] = (thread_connection_pool_t){.round_index = 0, .cons = vec_cons_with_capacity(8)};
    }

    if (! getStringFromJsonObject(&(state->host), settings, "host"))
    {
        LOGF("JSON Error: Http2Client->settings->host (string field) : The data was empty or invalid");
        return NULL;
    }
    getStringFromJsonObjectOrDefault(&(state->path), settings, "path", "/");

    if (! getIntFromJsonObject(&(state->host_port), settings, "port"))
    {
        LOGF("JSON Error: Http2Client->settings->port (number field) : The data was empty or invalid");
        return NULL;
    }

    getStringFromJsonObjectOrDefault(&(state->scheme), settings, "scheme", "https");

    char *content_type_buf = NULL;
    if (getStringFromJsonObject(&content_type_buf, settings, "content-type"))
    {
        state->content_type = httpContentTypeEnum(content_type_buf);
        free(content_type_buf);
    }

    getIntFromJsonObjectOrDefault(&(state->concurrency), settings, "concurrency", kDefaultConcurrency);

    nghttp2_option_new(&(state->ngoptions));
    nghttp2_option_set_peer_max_concurrent_streams(state->ngoptions, 0xffffffffU);
    nghttp2_option_set_no_closed_streams(state->ngoptions, 1);
    nghttp2_option_set_no_http_messaging(state->ngoptions, 1);
    // nghttp2_option_set_no_http_messaging use this with grpc?

    tunnel_t *t   = newTunnel();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;
    atomic_thread_fence(memory_order_release);
    return t;
}

api_result_t apiHttp2Client(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t){0};
}

tunnel_t *destroyHttp2Client(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataHttp2Client()
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
