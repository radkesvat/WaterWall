#include "http2_client.h"
#include "buffer_pool.h"
#include "helpers.h"
#include "tunnel.h"
#include "types.h"
#include "utils/jsonutils.h"


enum
{
    kDefaultConcurrency = 64 // cons will be muxed into 1
};

static int onStreamClosedCallBack(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *userdata)
{
    (void) error_code;
    (void) userdata;

    http2_client_con_state_t       *con    = (http2_client_con_state_t *) userdata;
    http2_client_child_con_state_t *stream = nghttp2_session_get_stream_user_data(session, stream_id);
    // LOGD("callback end stream for: %d", stream_id);

    // todo (optimize) nghttp2 is calling this callback even if we close the con ourselves
    // this should be omitted

    if (! stream)
    {
        return 0;
    }
    lockLine(stream->line);
    action_queue_t_push(&con->actions,
                        (http2_action_t) {.action_id = kActionStreamFinish, .stream_line = stream->line, .buf = NULL});

    return 0;
}

static void flushWriteQueue(http2_client_con_state_t *con)
{
    tunnel_t *self = con->tunnel;
    while (contextQueueLen(con->queue) > 0)
    {
        context_t *stream_context = contextQueuePop(con->queue);
        if (isAlive(stream_context->line)) // always true, since the stream is found before calling this
        {
            http2_client_child_con_state_t *stream = CSTATE(stream_context);

            lockLine(stream->line);
            action_queue_t_push(&con->actions, (http2_action_t) {.action_id   = kActionConData,
                                                                 .stream_line = stream->line,
                                                                 .buf         = stream_context->payload});
        }

        dropContexPayload(stream_context);
        destroyContext(stream_context);
    }
}

static int onHeaderCallBack(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen,
                            const uint8_t *value, size_t valuelen, uint8_t flags, void *userdata)
{
    // (void) name;
    (void) session;
    (void) namelen;
    (void) value;
    (void) valuelen;
    (void) flags;
    (void) userdata;
    (void) frame;
    (void) name;

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

static int onDataChunkRecvCallBack(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data,
                                   size_t len, void *userdata)
{
    (void) flags;
    if (UNLIKELY(userdata == NULL || len <= 0))
    {
        return 0;
    }
    http2_client_con_state_t *con = (http2_client_con_state_t *) userdata;

    http2_client_child_con_state_t *stream = nghttp2_session_get_stream_user_data(session, stream_id);

    if (UNLIKELY(! stream))
    {
        return 0;
    }

    sbuf_t *buf = bufferpoolPop(getLineBufferPool(con->line));
    sbufSetLength(buf, len);
    sbufWrite(buf, data, len);
    lockLine(stream->line);

    action_queue_t_push(
        &con->actions,
        (http2_action_t) {.action_id = kActionStreamDataReceived, .stream_line = stream->line, .buf = buf});

    return 0;
}

static int onFrameRecvCallBack(nghttp2_session *session, const nghttp2_frame *frame, void *userdata)
{
    (void) session;
    if (UNLIKELY(userdata == NULL))
    {
        return 0;
    }

    // LOGD("onFrameRecvCallBack\n");
    printFrameHd(&frame->hd);
    http2_client_con_state_t *con = (http2_client_con_state_t *) userdata;
    // tunnel_t                 *self = con->tunnel;

    switch (frame->hd.type)
    {
    case NGHTTP2_DATA:
        break;
    case NGHTTP2_HEADERS:
        break;
    case NGHTTP2_SETTINGS:
        break;
    case NGHTTP2_PING:
        con->no_ping_ack = false;
        break;
    case NGHTTP2_RST_STREAM:
    case NGHTTP2_WINDOW_UPDATE:
        // ignore
        return 0;
    default:
        break;
    }

    if ((frame->hd.type & NGHTTP2_HEADERS) == NGHTTP2_HEADERS)
    {
        if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) == NGHTTP2_FLAG_END_STREAM)
        {
            // LOGD("end stream for: %d", frame->hd.stream_id);

            http2_client_child_con_state_t *stream = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
            if (UNLIKELY(! stream))
            {
                return 0;
            }
            lockLine(stream->line);
            action_queue_t_push(
                &con->actions,
                (http2_action_t) {.action_id = kActionStreamFinish, .stream_line = stream->line, .buf = NULL});
        }

        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE)
        {
            con->handshake_completed = true;

            http2_client_child_con_state_t *stream =
                nghttp2_session_get_stream_user_data(con->session, frame->hd.stream_id);
            if (stream)
            {
                flushWriteQueue(con);
                lockLine(stream->line);
                action_queue_t_push(
                    &con->actions,
                    (http2_action_t) {.action_id = kActionStreamEst, .stream_line = stream->line, .buf = NULL});
            }
        }
    }

    return 0;
}

static void sendStreamData(http2_client_con_state_t *con, http2_client_child_con_state_t *stream, sbuf_t *buf)
{
    http2_flag flags = kHttP2FlagNone;
    if (UNLIKELY(! stream))
    {
        bufferpoolResuesbuf(getLineBufferPool(con->line), buf);
        return;
    }

    if (con->content_type == kApplicationGrpc)
    {
        grpc_message_hd msghd;
        msghd.flags  = 0;
        msghd.length = sbufGetBufLength(buf);
        flags        = kHttP2FlagNone;
        sbufShiftLeft(buf, GRPC_MESSAGE_HDLEN);
        grpcMessageHdPack(&msghd, sbufGetMutablePtr(buf));
    }

    http2_frame_hd framehd;
    framehd.length    = sbufGetBufLength(buf);
    framehd.type      = kHttP2Data;
    framehd.flags     = flags;
    framehd.stream_id = stream->stream_id;
    sbufShiftLeft(buf, HTTP2_FRAME_HDLEN);
    http2FrameHdPack(&framehd, sbufGetMutablePtr(buf));
    context_t *data                = newContext(con->line);
    data->payload                  = buf;
    line_t *h2_line = data->line;
    // make sure line is not freed, to be able to pause it
    lockLine(stream->line);
    con->current_stream_write_line = stream->line;
    con->tunnel->up->upStream(con->tunnel->up, data);
    unLockLine(stream->line);
    if (isAlive(h2_line))
    {
        con->current_stream_write_line = NULL;
    }
}

static bool sendNgHttp2Data(tunnel_t *self, http2_client_con_state_t *con)
{
    line_t *main_line = con->line;
    char   *buf       = NULL;
    size_t  len       = nghttp2_session_mem_send(con->session, (const uint8_t **) &buf);

    if (len > 0)
    {
        sbuf_t *send_buf = bufferpoolPop(getLineBufferPool(main_line));
        sbufSetLength(send_buf, len);
        sbufWrite(send_buf, buf, len);
        context_t *data = newContext(main_line);
        data->payload   = send_buf;
        self->up->upStream(self->up, data);
        return true;
    }

    return false;
}

static void doHttp2Action(const http2_action_t action, http2_client_con_state_t *con)
{
    line_t   *main_line = con->line;
    tunnel_t *self      = con->tunnel;

    if (! isAlive(action.stream_line))
    {
        if (action.buf)
        {
            bufferpoolResuesbuf(getLineBufferPool(action.stream_line), action.buf);
        }
        unLockLine(action.stream_line);
        return;
    }

    http2_client_child_con_state_t *stream = LSTATE(action.stream_line);

    assert(stream); // when the line is alive, there is no way that we lose the state

    switch (action.action_id)
    {
    default:

    case kActionStreamEst: {

        stream->tunnel->dw->downStream(stream->tunnel->dw, newEstContext(stream->line));
    }

    break;

    case kActionStreamDataReceived: {
        if (con->content_type == kApplicationGrpc)
        {
            bufferStreamPush(stream->grpc_buffer_stream, action.buf);

            while (true)
            {
                if (stream->grpc_bytes_needed == 0 && bufferStreamLen(stream->grpc_buffer_stream) >= GRPC_MESSAGE_HDLEN)
                {
                    sbuf_t *gheader_buf = bufferStreamRead(stream->grpc_buffer_stream, GRPC_MESSAGE_HDLEN);
                    grpc_message_hd msghd;
                    grpcMessageHdUnpack(&msghd, sbufGetRawPtr(gheader_buf));
                    stream->grpc_bytes_needed = msghd.length;
                    bufferpoolResuesbuf(getLineBufferPool(con->line), gheader_buf);
                }
                if (stream->grpc_bytes_needed > 0 &&
                    bufferStreamLen(stream->grpc_buffer_stream) >= stream->grpc_bytes_needed)
                {
                    sbuf_t *gdata_buf = bufferStreamRead(stream->grpc_buffer_stream, stream->grpc_bytes_needed);
                    stream->grpc_bytes_needed = 0;

                    context_t *stream_data = newContext(stream->line);
                    stream_data->payload   = gdata_buf;

                    stream->tunnel->dw->downStream(stream->tunnel->dw, stream_data);

                    // check http2 connection is alive
                    if (! isAlive(action.stream_line) || ! isAlive(main_line))
                    {
                        unLockLine(action.stream_line);
                        return;
                    }

                    continue;
                }
                break;
            }
        }
        else
        {
            sbuf_t *buf         = action.buf;
            context_t      *stream_data = newContext(stream->line);
            stream_data->payload        = buf;
            stream->tunnel->dw->downStream(stream->tunnel->dw, stream_data);
        }
        if (! isAlive(action.stream_line) || ! isAlive(main_line))
        {
            unLockLine(action.stream_line);
            return;
        }
    }
    break;

    case kActionStreamFinish: {
        context_t *fc   = newFinContext(stream->line);
        tunnel_t  *dest = stream->tunnel->dw;
        nghttp2_session_set_stream_user_data(con->session, stream->stream_id, NULL);
        removeStream(con, stream);
        deleteHttp2Stream(stream);
        dest->downStream(dest, fc);
    }
    break;
    case kActionConData: {
        sendStreamData(con, stream, action.buf);
    }
    break;
    case kActionInvalid:
        LOGF("incorrect http2 action id");
        exit(1);
        break;
    }
    unLockLine(action.stream_line);
}

static void upStream(tunnel_t *self, context_t *c)
{
    http2_client_state_t *state = TSTATE(self);

    if (c->payload != NULL)
    {
        http2_client_child_con_state_t *stream = CSTATE(c);
        http2_client_con_state_t       *con    = LSTATE(stream->parent);

        if (! con->handshake_completed)
        {
            contextQueuePush(con->queue, c);
            return;
        }

        lockLine(con->line);

        while (sendNgHttp2Data(self, con))
        {
            if (! isAlive(con->line))
            {
                unLockLine(con->line);
                destroyContext(c);
                return;
            }
        }

        sendStreamData(con, stream, c->payload);
        
        unLockLine(con->line);

        dropContexPayload(c);
        destroyContext(c);
    }
    else
    {
        if (c->init)
        {
            http2_client_con_state_t       *con    = takeHttp2Connection(self, c->line->tid);
            http2_client_child_con_state_t *stream = createHttp2Stream(con, c->line);
            CSTATE_MUT(c)                          = stream;
            nghttp2_session_set_stream_user_data(con->session, stream->stream_id, stream);
            lockLine(con->line);

            if (! con->init_sent)
            {
                con->init_sent = true;
                self->up->upStream(self->up, newInitContext(con->line));
                if (! isAlive(con->line))
                {
                    unLockLine(con->line);
                    destroyContext(c);
                    return;
                }
            }

            while (sendNgHttp2Data(self, con))
            {
                if (! isAlive(con->line))
                {
                    unLockLine(con->line);
                    destroyContext(c);
                    return;
                }
            }
            unLockLine(con->line);

            destroyContext(c);
        }
        else if (c->fin)
        {
            http2_client_child_con_state_t *stream = CSTATE(c);
            http2_client_con_state_t       *con    = LSTATE(stream->parent);
            CSTATE_DROP(c);

            int flags = NGHTTP2_FLAG_END_STREAM | NGHTTP2_FLAG_END_HEADERS;
            if (con->content_type == kApplicationGrpc)
            {
                nghttp2_nv nv = makeNV("grpc-status", "0");
                nghttp2_submit_headers(con->session, flags, stream->stream_id, NULL, &nv, 1, NULL);
            }
            else
            {
                nghttp2_submit_headers(con->session, flags, stream->stream_id, NULL, NULL, 0, NULL);
            }
            // LOGD("closing -> %d", (int) stream->stream_id);
            nghttp2_session_set_stream_user_data(con->session, stream->stream_id, NULL);
            removeStream(con, stream);
            deleteHttp2Stream(stream);

            lockLine(con->line);
            while (sendNgHttp2Data(self, con))
            {
                if (! isAlive(con->line))
                {
                    unLockLine(con->line);
                    destroyContext(c);
                    return;
                }
            }
            unLockLine(con->line);

            if (con->root.next == NULL && con->childs_added >= state->concurrency)
            {
                context_t *con_fc   = newFinContext(con->line);
                tunnel_t  *con_dest = con->tunnel->up;
                deleteHttp2Connection(con);
                con_dest->upStream(con_dest, con_fc);
            }

            destroyContext(c);
            return;
        }
    }
}

static void downStream(tunnel_t *self, context_t *c)
{
    http2_client_state_t     *state = TSTATE(self);
    http2_client_con_state_t *con   = CSTATE(c);
    if (c->payload != NULL)
    {
        size_t len = 0;
        while ((len = sbufGetBufLength(c->payload)) > 0)
        {
            size_t  consumed = min(1 << 15UL, (ssize_t) len);
            ssize_t ret      = nghttp2_session_mem_recv2(con->session, (const uint8_t *) sbufGetRawPtr(c->payload), consumed);
            sbufShiftRight(c->payload, consumed);

            if (ret != (ssize_t) consumed)
            {
                // assert(false);
                deleteHttp2Connection(con);
                self->up->upStream(self->up, newFinContext(c->line));
                reuseContextPayload(c);
                destroyContext(c);
                return;
            }

            while (sendNgHttp2Data(self, con))
            {
                if (! isAlive(c->line))
                {
                    reuseContextPayload(c);
                    destroyContext(c);
                    return;
                }
            }

            while (action_queue_t_size(&con->actions) > 0)
            {
                const http2_action_t action = action_queue_t_pull_front(&con->actions);
                doHttp2Action(action, con);
                if (! isAlive(c->line))
                {
                    reuseContextPayload(c);
                    destroyContext(c);
                    return;
                }
            }

            while (sendNgHttp2Data(self, con))
            {
                if (! isAlive(c->line))
                {
                    reuseContextPayload(c);
                    destroyContext(c);
                    return;
                }
            }
            if (nghttp2_session_want_read(con->session) == 0 && nghttp2_session_want_write(con->session) == 0)
            {
                context_t *fin_ctx = newFinContext(con->line);
                deleteHttp2Connection(con);
                self->up->upStream(self->up, fin_ctx);
                reuseContextPayload(c);
                destroyContext(c);
                return;
            }
        }

        if (con->root.next == NULL && con->childs_added >= state->concurrency)
        {
            context_t *con_fc = newFinContext(con->line);
            deleteHttp2Connection(con);
            self->up->upStream(self->up, con_fc);
        }

        reuseContextPayload(c);
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
        memoryAllocate(sizeof(http2_client_state_t) + (getWorkersCount() * sizeof(thread_connection_pool_t)));
    memorySet(state, 0, sizeof(http2_client_state_t));
    cJSON *settings = instance_info->node_settings_json;

    nghttp2_session_callbacks_new(&(state->cbs));
    nghttp2_session_callbacks_set_on_header_callback(state->cbs, onHeaderCallBack);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(state->cbs, onDataChunkRecvCallBack);
    nghttp2_session_callbacks_set_on_frame_recv_callback(state->cbs, onFrameRecvCallBack);
    nghttp2_session_callbacks_set_on_stream_close_callback(state->cbs, onStreamClosedCallBack);

    for (size_t i = 0; i < getWorkersCount(); i++)
    {
        state->thread_cpool[i] = (thread_connection_pool_t) {.round_index = 0, .cons = vec_cons_with_capacity(8)};
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
        memoryFree(content_type_buf);
    }

    int int_concurrency;
    getIntFromJsonObjectOrDefault(&(int_concurrency), settings, "concurrency", kDefaultConcurrency);
    state->concurrency = int_concurrency;

    nghttp2_option_new(&(state->ngoptions));
    nghttp2_option_set_peer_max_concurrent_streams(state->ngoptions, 0xffffffffU);
    nghttp2_option_set_no_closed_streams(state->ngoptions, 1);
    nghttp2_option_set_no_http_messaging(state->ngoptions, 1);
    // nghttp2_option_set_no_http_messaging use this with grpc?

    tunnel_t *t   = newTunnel();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;

    return t;
}

api_result_t apiHttp2Client(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t) {0};
}

tunnel_t *destroyHttp2Client(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataHttp2Client(void)
{
    return (tunnel_metadata_t) {.version = 0001, .flags = 0x0};
}
