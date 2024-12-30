#include "http2_server.h"
#include "grpc_def.h"
#include "helpers.h"
#include "http2_def.h"
#include "loggers/network_logger.h"
#include "nghttp2/nghttp2.h"
#include "types.h"
#include "utils/mathutils.h"

static int onStreamClosedCallback(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *userdata)
{
    (void) error_code;

    http2_server_con_state_t       *con    = (http2_server_con_state_t *) userdata;
    http2_server_child_con_state_t *stream = nghttp2_session_get_stream_user_data(session, stream_id);
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

static int onHeaderCallback(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen,
                            const uint8_t *value, size_t valuelen, uint8_t flags, void *userdata)
{
    (void) session;
    (void) namelen;
    (void) valuelen;
    (void) flags;
    if (UNLIKELY(userdata == NULL))
    {
        return 0;
    }

    // LOGD("onHeaderCallback\n");
    printFrameHd(&frame->hd);

    // LOGD("%s: %s\n", name, value);

    http2_server_con_state_t *con = (http2_server_con_state_t *) userdata;

    if (*name == ':')
    {
        // todo (http2headers) these should be saved somewhere, idk if they will be useful or not
        // if (strcmp(name, ":method") == 0)
        // {
        //     // req->method = http_method_enum(value);
        // }
        // else if (strcmp(name, ":path") == 0)
        // {
        //     // req->url = value;
        // }
        // else if (strcmp(name, ":scheme") == 0)
        // {
        //     // req->headers["Scheme"] = value;
        // }
        // else if (strcmp(name, ":authority") == 0)
        // {
        //     // req->headers["Host"] = value;
        // }
    }
    else
    {
        // hp->parsed->headers[name] = value;
        if (strcmp((const char *) name, "content-type") == 0)
        {
            con->content_type = httpContentTypeEnum((const char *) value);
        }
    }

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
    http2_server_con_state_t *con = (http2_server_con_state_t *) userdata;

    http2_server_child_con_state_t *stream = nghttp2_session_get_stream_user_data(session, stream_id);
    if (UNLIKELY(! stream))
    {
        return 0;
    }

    shift_buffer_t *buf = popBuffer(getLineBufferPool(con->line));
    setLen(buf, len);
    writeRaw(buf, data, len);

    lockLine(stream->line);
    action_queue_t_push(
        &con->actions,
        (http2_action_t) {.action_id = kActionStreamDataReceived, .stream_line = stream->line, .buf = buf});
    return 0;
}

static int onFrameRecvCallback(nghttp2_session *session, const nghttp2_frame *frame, void *userdata)
{
    (void) session;
    if (UNLIKELY(userdata == NULL))
    {
        return 0;
    }

    printFrameHd(&frame->hd);
    http2_server_con_state_t *con = (http2_server_con_state_t *) userdata;

    switch (frame->hd.type)
    {
    case NGHTTP2_DATA:
        break;
    case NGHTTP2_HEADERS:
        break;
    case NGHTTP2_SETTINGS:
        break;
    case NGHTTP2_PING:
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

            http2_server_child_con_state_t *stream = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
            if (UNLIKELY(! stream))
            {
                return 0;
            }
            lockLine(stream->line);
            action_queue_t_push(
                &con->actions,
                (http2_action_t) {.action_id = kActionStreamFinish, .stream_line = stream->line, .buf = NULL});
            return 0;
        }

        if (frame->headers.cat == NGHTTP2_HCAT_REQUEST)
        {

            nghttp2_nv nvs[10];
            int        nvlen = 0;
            nvs[nvlen++]     = makeNV(":status", "200");
            if (con->content_type == kApplicationGrpc)
            {
                // correct content_type: application/grpc
                nvs[nvlen++] = makeNV("content-type", httpContentTypeStr(kApplicationGrpc));
                nvs[nvlen++] = makeNV("accept-encoding", "identity");
            }

            int flags = NGHTTP2_FLAG_END_HEADERS;

            nghttp2_submit_headers(con->session, flags, frame->hd.stream_id, NULL, &nvs[0], nvlen, NULL);

            http2_server_child_con_state_t *stream =
                createHttp2Stream(con, con->line, con->tunnel, frame->hd.stream_id);
            addStream(con, stream);

            lockLine(stream->line);
            action_queue_t_push(
                &con->actions,
                (http2_action_t) {.action_id = kActionStreamInit, .stream_line = stream->line, .buf = NULL});
        }
    }
    return 0;
}



static void sendStreamResposnseData(http2_server_con_state_t *con, http2_server_child_con_state_t *stream,
                                    shift_buffer_t *buf)
{
    http2_flag flags = kHttP2FlagNone;
    if (UNLIKELY(! stream))
    {
        reuseBuffer(getLineBufferPool(con->line), buf);
        return;
    }

    if (con->content_type == kApplicationGrpc)
    {
        grpc_message_hd msghd;
        msghd.flags  = 0;
        msghd.length = bufLen(buf);
        flags        = kHttP2FlagNone;
        shiftl(buf, GRPC_MESSAGE_HDLEN);
        grpcMessageHdPack(&msghd, rawBufMut(buf));
    }

    http2_frame_hd framehd;
    framehd.length    = bufLen(buf);
    framehd.type      = kHttP2Data;
    framehd.flags     = flags;
    framehd.stream_id = stream->stream_id;
    shiftl(buf, HTTP2_FRAME_HDLEN);
    http2FrameHdPack(&framehd, rawBufMut(buf));
    context_t *response_data = newContext(con->line);
    response_data->payload   = buf;
    con->tunnel->dw->downStream(con->tunnel->dw, response_data);
}

static bool sendNgHttp2Data(tunnel_t *self, http2_server_con_state_t *con)
{
    line_t *main_line = con->line;
    char   *data      = NULL;
    size_t  len       = nghttp2_session_mem_send(con->session, (const uint8_t **) &data);

    if (len > 0)
    {
        shift_buffer_t *send_buf = reserveBufSpace(popBuffer(getLineBufferPool(main_line)),len);
        setLen(send_buf, len);
        writeRaw(send_buf, data, len);
        context_t *response_data = newContext(main_line);
        response_data->payload   = send_buf;
        self->dw->downStream(self->dw, response_data);
        return true;
    }

    return false;
}

static void doHttp2Action(const http2_action_t action, http2_server_con_state_t *con)
{
    line_t   *main_line = con->line;
    tunnel_t *self      = con->tunnel;
    if (! isAlive(action.stream_line))
    {
        if (action.buf)
        {
            reuseBuffer(getLineBufferPool(action.stream_line), action.buf);
        }
        unLockLine(action.stream_line);
        return;
    }
    http2_server_child_con_state_t *stream = LSTATE(action.stream_line);

    assert(stream); // when the line is alive, there is no way that we lose the state

    switch (action.action_id)
    {

    case kActionStreamInit: {

        stream->tunnel->up->upStream(stream->tunnel->up, newInitContext(stream->line));
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
                    shift_buffer_t *gheader_buf = bufferStreamRead(stream->grpc_buffer_stream, GRPC_MESSAGE_HDLEN);
                    grpc_message_hd msghd;
                    grpcMessageHdUnpack(&msghd, rawBuf(gheader_buf));
                    stream->grpc_bytes_needed = msghd.length;
                    reuseBuffer(getLineBufferPool(con->line), gheader_buf);
                }
                if (stream->grpc_bytes_needed > 0 &&
                    bufferStreamLen(stream->grpc_buffer_stream) >= stream->grpc_bytes_needed)
                {
                    shift_buffer_t *gdata_buf = bufferStreamRead(stream->grpc_buffer_stream, stream->grpc_bytes_needed);
                    stream->grpc_bytes_needed = 0;

                    context_t *stream_data = newContext(stream->line);
                    stream_data->payload   = gdata_buf;
                    stream->tunnel->up->upStream(stream->tunnel->up, stream_data);

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
            shift_buffer_t *buf         = action.buf;
            context_t      *stream_data = newContext(stream->line);

            stream_data->payload = buf;
            stream->tunnel->up->upStream(stream->tunnel->up, stream_data);
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
        tunnel_t  *dest = stream->tunnel->up;
        nghttp2_session_set_stream_user_data(con->session, stream->stream_id, NULL);
        removeStream(con, stream);
        deleteHttp2Stream(stream);
        dest->upStream(dest, fc);
    }
    break;

    default:
    case kActionInvalid:
        LOGF("incorrect http2 action id");
        exit(1);
        break;
    }

    unLockLine(action.stream_line);
}

static void upStream(tunnel_t *self, context_t *c)
{
    if (c->payload != NULL)
    {
        http2_server_con_state_t *con = CSTATE(c);
        size_t                    len = 0;

        while ((len = bufLen(c->payload)) > 0)
        {
            size_t  consumed = min(1 << 15UL, (ssize_t) len);
            ssize_t ret      = nghttp2_session_mem_recv2(con->session, (const uint8_t *) rawBuf(c->payload), consumed);
            shiftr(c->payload, consumed);

            if (ret != (ssize_t) consumed)
            {
                // assert(false);
                deleteHttp2Connection(con);
                self->dw->downStream(self->dw, newFinContext(c->line));
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
                self->dw->downStream(self->dw, fin_ctx);
                reuseContextPayload(c);
                destroyContext(c);
                return;
            }
        }

        reuseContextPayload(c);
        destroyContext(c);
    }
    else
    {
        if (c->init)
        {
            CSTATE_MUT(c) = createHttp2Connection(self, c->line);
            self->dw->downStream(self->dw, newEstContext(c->line));

            destroyContext(c);
        }
        else if (c->fin)
        {
            deleteHttp2Connection(CSTATE(c));
            destroyContext(c);
        }
    }
}

static void downStream(tunnel_t *self, context_t *c)
{
    http2_server_child_con_state_t *stream = CSTATE(c);
    http2_server_con_state_t       *con    = LSTATE(stream->parent);

    if (c->payload != NULL)
    {
        lockLine(con->line);
        while (sendNgHttp2Data(self, con))
        {
            if (! isAlive(con->line))
            {
                unLockLine(con->line);
                reuseContextPayload(c);
                destroyContext(c);
                return;
            }
        }
        unLockLine(con->line);

        sendStreamResposnseData(con, stream, c->payload);
        dropContexPayload(c);
        destroyContext(c);
    }
    else
    {
        if (c->fin)
        {
            if (con->content_type == kApplicationGrpc)
            {
                nghttp2_nv nv = makeNV("grpc-status", "0");
                nghttp2_submit_trailer(con->session, stream->stream_id, &nv, 1);
            }
            else
            {
                nghttp2_submit_trailer(con->session, stream->stream_id, NULL, 0);
            }

            // LOGE("closing -> %d", stream->stream_id);
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

            if (nghttp2_session_want_read(con->session) == 0 && nghttp2_session_want_write(con->session) == 0)
            {
                context_t *fin_ctx = newFinContext(con->line);
                deleteHttp2Connection(con);
                self->dw->downStream(self->dw, fin_ctx);
            }

            destroyContext(c);
        }
        else
        {
            destroyContext(c);
        }
    }
}

tunnel_t *newHttp2Server(node_instance_context_t *instance_info)
{
    (void) instance_info;
    http2_server_state_t *state = memoryAllocate(sizeof(http2_server_state_t));
    memset(state, 0, sizeof(http2_server_state_t));

    nghttp2_session_callbacks_new(&(state->cbs));
    nghttp2_session_callbacks_set_on_header_callback(state->cbs, onHeaderCallback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(state->cbs, onDataChunkRecvCallback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(state->cbs, onFrameRecvCallback);
    nghttp2_session_callbacks_set_on_stream_close_callback(state->cbs, onStreamClosedCallback);

    nghttp2_option_new(&(state->ngoptions));
    nghttp2_option_set_peer_max_concurrent_streams(state->ngoptions, kMaxConcurrentStreams);
    nghttp2_option_set_no_closed_streams(state->ngoptions, 1);
    nghttp2_option_set_no_http_messaging(state->ngoptions, 1);

    tunnel_t *t   = newTunnel();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;

    return t;
}

api_result_t apiHttp2Server(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t) {0};
}

tunnel_t *destroyHttp2Server(tunnel_t *self)
{
    (void) (self);

    return NULL;
}

tunnel_metadata_t getMetadataHttp2Server(void)
{
    return (tunnel_metadata_t) {.version = 0001, .flags = 0x0};
}
