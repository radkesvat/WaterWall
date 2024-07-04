#include "http2_server.h"
#include "grpc_def.h"
#include "helpers.h"
#include "http2_def.h"
#include "loggers/network_logger.h"
#include "nghttp2/nghttp2.h"
#include "types.h"
#include "utils/mathutils.h"

static int onHeaderCallback(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *_name, size_t namelen,
                            const uint8_t *_value, size_t valuelen, uint8_t flags, void *userdata)
{
    (void) session;
    (void) namelen;
    (void) valuelen;
    (void) flags;
    if (WW_UNLIKELY(userdata == NULL))
    {
        return 0;
    }

    // LOGD("onHeaderCallback\n");
    printFrameHd(&frame->hd);
    const char *name  = (const char *) _name;
    const char *value = (const char *) _value;
    // LOGD("%s: %s\n", name, value);

    http2_server_con_state_t *con = (http2_server_con_state_t *) userdata;

    if (*name == ':')
    {
        // todo (http2headers) these should be saved somewhere
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
        if (strcmp(name, "content-type") == 0)
        {
            con->content_type = httpContentTypeEnum(value);
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
    if (! stream)
    {
        return 0;
    }

    // LOGD("onDataChunkRecvCallback\n");
    // LOGD("stream_id=%d length=%d\n", stream_id, (int)len);
    // LOGD("up: %d\n", (int)len);

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
                if (! stream->first_sent)
                {
                    stream->first_sent = true;
                    stream_data->first = true;
                }
                stream->tunnel->up->upStream(stream->tunnel->up, stream_data);

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
        if (! stream->first_sent)
        {
            stream->first_sent = true;
            stream_data->first = true;
        }
        stream->tunnel->up->upStream(stream->tunnel->up, stream_data);
    }

    return 0;
}

static int onFrameRecvCallback(nghttp2_session *session, const nghttp2_frame *frame, void *userdata)
{
    if (WW_UNLIKELY(userdata == NULL))
    {
        return 0;
    }
    // LOGD("onFrameRecvCallback\n");
    printFrameHd(&frame->hd);
    http2_server_con_state_t *con  = (http2_server_con_state_t *) userdata;
    tunnel_t                 *self = con->tunnel;

    switch (frame->hd.type)
    {
    case kHttP2Data:
        con->state = kH2RecvData;
        break;
    case kHttP2Headers:
        con->state = kH2RecvHeaders;
        break;
    case kHttP2Settings:
        con->state = kH2RecvSettings;
        break;
    case kHttP2Ping:
        // LOGW("Http2Client: GOT PING");
        con->state = kH2RecvPing;
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

    if ((frame->hd.flags & kHttP2FlagEndStream) == kHttP2FlagEndStream)
    {
        http2_server_child_con_state_t *stream = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
        if (! stream)
        {
            return 0;
        }
        resumeLineDownSide(stream->parent);
        nghttp2_session_set_stream_user_data(con->session, stream->stream_id, NULL);
        context_t *fc   = newFinContext(stream->line);
        tunnel_t  *dest = stream->tunnel->up;
        CSTATE_DROP(fc);
        removeStream(con, stream);
        deleteHttp2Stream(stream);
        dest->upStream(dest, fc);
        return 0;
    }

    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST)
    {
        return 0;
    }

    nghttp2_nv nvs[10];
    int        nvlen = 0;
    nvs[nvlen++]     = makeNv(":status", "200");
    if (con->content_type == kApplicationGrpc)
    {
        // correct content_type: application/grpc
        nvs[nvlen++] = makeNv("content-type", httpContentTypeStr(kApplicationGrpc));
        nvs[nvlen++] = makeNv("accept-encoding", "identity");
    }

    int flags = NGHTTP2_FLAG_END_HEADERS;

    nghttp2_submit_headers(con->session, flags, frame->hd.stream_id, NULL, &nvs[0], nvlen, NULL);
    con->state = kH2SendHeaders;

    http2_server_child_con_state_t *stream = createHttp2Stream(con, con->line, self, frame->hd.stream_id);
    addStream(con, stream);
    stream->tunnel->up->upStream(stream->tunnel->up, newInitContext(stream->line));

    return 0;
}

static bool trySendResponse(tunnel_t *self, http2_server_con_state_t *con, size_t stream_id, shift_buffer_t *buf)
{
    line_t *line = con->line;
    // http2_server_con_state_t *con = ((http2_server_con_state_t *)(((line->chains_state)[self->chain_index])));
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
        context_t *response_data = newContext(line);
        response_data->payload   = send_buf;
        self->dw->downStream(self->dw, response_data);

        return true;
    }
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
        context_t *response_data = newContext(line);
        response_data->payload   = buf;
        self->dw->downStream(self->dw, response_data);

        goto send_done;
    }
    else if (con->state == kH2SendData)
    {
    send_done:;
        con->state = kH2SendDone;
    }

    return false;
}

static void upStream(tunnel_t *self, context_t *c)
{
    if (c->payload != NULL)
    {
        http2_server_con_state_t *con = CSTATE(c);
        size_t                    len = 0;

        while ((len = bufLen(c->payload)) > 0)
        {
            size_t consumed = min(1 << 15UL, (ssize_t) len);
            con->state      = kH2WantRecv;
            ssize_t ret     = nghttp2_session_mem_recv2(con->session, (const uint8_t *) rawBuf(c->payload), consumed);
            shiftr(c->payload, consumed);

            if (! isAlive(c->line))
            {
                reuseContextPayload(c);
                destroyContext(c);
                return;
            }

            if (ret != (ssize_t) consumed)
            {
                assert(false);
                deleteHttp2Connection(con);
                self->dw->downStream(self->dw, newFinContext(c->line));
                reuseContextPayload(c);
                destroyContext(c);
                return;
            }

            if (nghttp2_session_want_write(con->session) != 0)
            {

                while (trySendResponse(self, con, 0, NULL))
                {
                    if (! isAlive(c->line))
                    {
                        reuseContextPayload(c);
                        destroyContext(c);
                        return;
                    }
                }
            }
            if (nghttp2_session_want_read(con->session) == 0 && nghttp2_session_want_write(con->session) == 0)
            {
                assert(false);
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
        con->state = kH2SendHeaders;
        while (trySendResponse(self, con, stream->stream_id, c->payload))
        {
            if (! isAlive(c->line))
            {
                destroyContext(c);
                return;
            }
        }

        dropContexPayload(c);
        destroyContext(c);
    }
    else
    {
        if (c->fin)
        {
            CSTATE_DROP(c);

            int flags = NGHTTP2_FLAG_END_STREAM | NGHTTP2_FLAG_END_HEADERS;
            if (con->content_type == kApplicationGrpc)
            {
                nghttp2_nv nv = makeNv("grpc-status", "0");
                nghttp2_submit_headers(con->session, flags, stream->stream_id, NULL, &nv, 1, NULL);
            }
            else
            {
                nghttp2_submit_headers(con->session, flags, stream->stream_id, NULL, NULL, 0, NULL);
            }

            resumeLineDownSide(con->line);
            nghttp2_session_set_stream_user_data(con->session, stream->stream_id, NULL);
            removeStream(con, stream);
            deleteHttp2Stream(stream);

            lockLine(con->line);
            while (trySendResponse(self, con, 0, NULL))
            {
                if (! isAlive(con->line))
                {
                    unLockLine(con->line);
                    destroyContext(c);
                    return;
                }
            }
            if (! isAlive(con->line))
            {
                unLockLine(con->line);
                destroyContext(c);
                return;
            }
            unLockLine(con->line);

            if (nghttp2_session_want_read(con->session) == 0 && nghttp2_session_want_write(con->session) == 0)
            {
                context_t *fin_ctx = newFinContext(con->line);
                deleteHttp2Connection(con);
                self->dw->downStream(self->dw, fin_ctx);
            }

            destroyContext(c);
            return;
        }
        {
            destroyContext(c);
        }
    }
}

tunnel_t *newHttp2Server(node_instance_context_t *instance_info)
{
    (void) instance_info;
    http2_server_state_t *state = wwmGlobalMalloc(sizeof(http2_server_state_t));
    memset(state, 0, sizeof(http2_server_state_t));

    nghttp2_session_callbacks_new(&(state->cbs));
    nghttp2_session_callbacks_set_on_header_callback(state->cbs, onHeaderCallback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(state->cbs, onDataChunkRecvCallback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(state->cbs, onFrameRecvCallback);

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
    return (api_result_t){0};
}

tunnel_t *destroyHttp2Server(tunnel_t *self)
{
    (void) (self);

    return NULL;
}

tunnel_metadata_t getMetadataHttp2Server(void)
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
