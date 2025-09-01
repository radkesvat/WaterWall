#include "structure.h"

#include "loggers/network_logger.h"

static inline void printFrameHd(const nghttp2_frame_hd *hd)
{
    discard hd;
    LOGD("[frame] length=%d type=%x flags=%x stream_id=%d\n", (int) hd->length, (int) hd->type, (int) hd->flags,
         hd->stream_id);
}

nghttp2_nv makeNV(const char *name, const char *value)
{
    nghttp2_nv nv;
    nv.name     = (uint8_t *) name;
    nv.value    = (uint8_t *) value;
    nv.namelen  = strlen(name);
    nv.valuelen = strlen(value);
    nv.flags    = NGHTTP2_NV_FLAG_NONE;
    return nv;
}

sbuf_t *httpclientV2MakeFrame(bool is_grpc, unsigned int stream_id, sbuf_t *buf)
{
    http2_flag flags = kHttP2FlagNone;

    discard is_grpc;
    // if (ls->content_type == kApplicationGrpc)
    // {
    //     grpc_message_hd msghd;
    //     msghd.flags  = 0;
    //     msghd.length = sbufGetBufLength(buf);
    //     flags        = kHttP2FlagNone;
    //     sbufShiftLeft(buf, GRPC_MESSAGE_HDLEN);
    //     grpcMessageHdPack(&msghd, sbufGetMutablePtr(buf));
    // }

    http2_frame_hd framehd;
    framehd.length    = sbufGetLength(buf);
    framehd.type      = kHttP2Data;
    framehd.flags     = flags;
    framehd.stream_id = stream_id;
    sbufShiftLeft(buf, HTTP2_FRAME_HDLEN);
    http2FrameHdPack(&framehd, sbufGetMutablePtr(buf));

    return buf;
}

static void flushWriteQueue(httpclient_lstate_t *ls)
{
    while (bufferqueueGetBufCount(&ls->bq) > 0)
    {
        sbuf_t *buf = bufferqueuePopFront(&ls->bq);
        contextqueuePush(&ls->cq, contextCreatePayload(ls->line, buf));
    }
}

static sbuf_t *httpclientV2GetNgHttp2SendableData(httpclient_lstate_t *ls)
{
    char  *buf = NULL;
    size_t len = nghttp2_session_mem_send2(ls->session, (const uint8_t **) &buf);

    if (len > 0)
    {
        sbuf_t *sbuf = bufferpoolGetLargeBuffer(getWorkerBufferPool(lineGetWID(ls->line)));
        sbufSetLength(sbuf, len);
        sbufWriteLarge(sbuf, buf, len);
        return sbuf;
    }

    return NULL;
}
bool httpclientV2PullAndSendNgHttp2SendableData(tunnel_t *t, httpclient_lstate_t *ls)
{
    lineLock(ls->line);

    sbuf_t *send_buf = httpclientV2GetNgHttp2SendableData(ls);

    while (send_buf != NULL)
    {
        tunnelNextUpStreamPayload(t, ls->line, send_buf);

        if (! lineIsAlive(ls->line))
        {
            lineUnlock(ls->line);
            return false;
        }

        send_buf = httpclientV2GetNgHttp2SendableData(ls);
    }
    lineUnlock(ls->line);
    return true;
}


int httpclientV2OnHeaderCallBack(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name,
                                 size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *userdata)
{
    // discard name;
    discard session;
    discard namelen;
    discard value;
    discard valuelen;
    discard flags;
    discard userdata;
    discard frame;
    discard name;

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

int httpclientV2OnDataChunkRecvCallBack(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data,
                                        size_t len, void *userdata)
{
    discard session;
    discard flags;
    if (UNLIKELY(userdata == NULL || len <= 0))
    {
        return 0;
    }
    assert(stream_id == 0);

    httpclient_lstate_t *ls = (httpclient_lstate_t *) userdata;

    sbuf_t *buf = bufferpoolGetLargeBuffer(getWorkerBufferPool(lineGetWID(ls->line)));
    sbufSetLength(buf, len);
    sbufWriteLarge(buf, data, len);

    contextqueuePush(&ls->cq_d, contextCreatePayload(ls->line, buf));

    return 0;
}

int httpclientV2OnFrameRecvCallBack(nghttp2_session *session, const nghttp2_frame *frame, void *userdata)
{
    discard session;
    if (UNLIKELY(userdata == NULL))
    {
        return 0;
    }

    // LOGD("onFrameRecvCallBack\n");
    printFrameHd(&frame->hd);
    httpclient_lstate_t *ls = (httpclient_lstate_t *) userdata;

    switch (frame->hd.type)
    {
    case NGHTTP2_DATA:
    case NGHTTP2_HEADERS:
    case NGHTTP2_SETTINGS:
        break;
    case NGHTTP2_PING:;
        // ls->no_ping_ack = false;
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
        // if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) == NGHTTP2_FLAG_END_STREAM)
        // {
        //     // LOGD("end stream for: %d", frame->hd.stream_id);
        //     http2_client_stream_state_t *stream = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
        //     if (UNLIKELY(! stream))
        //     {
        //         return 0;
        //     }
        //     nghttp2_session_set_stream_user_data(session, frame->hd.stream_id, NULL);
        //     contextqueuePush(&ls->cq_d, contextCreateFin(stream->line));
        // }

        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE)
        {
            assert(ls->stream_id == 0);
            ls->handshake_completed = true;
            ls->stream_id           = frame->hd.stream_id;

            flushWriteQueue(ls);
        }
    }

    return 0;
}

int httpclientV2OnStreamClosedCallBack(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *userdata)
{
    discard error_code;
    discard userdata;

    if (UNLIKELY(userdata == NULL))
    {
        return 0;
    }

    httpclient_lstate_t *ls = (httpclient_lstate_t *) userdata;
    // http2_client_stream_state_t *stream = nghttp2_session_get_stream_user_data(session, stream_id);
    // LOGD("callback end stream for: %d", stream_id);

    LOGD("Http2Client: callback end stream for: %d", stream_id);
    nghttp2_session_set_stream_user_data(session, stream_id, NULL);
    contextqueuePush(&ls->cq_d, contextCreateFin(ls->line));
    return 0;
}
