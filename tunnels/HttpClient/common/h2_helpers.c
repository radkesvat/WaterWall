#include "structure.h"

#include "loggers/network_logger.h"

static inline void printFrameHd(const nghttp2_frame_hd *hd)
{
    (void) hd;
    LOGD("[frame] length=%d type=%x flags=%x stream_id=%d\n", (int) hd->length, (int) hd->type, (int) hd->flags,
         hd->stream_id);
}

// static void sendStreamData(http2_client_con_state_t *con, http2_client_child_con_state_t *stream, sbuf_t *buf)
// {
//     http2_flag flags = kHttP2FlagNone;
//     if (UNLIKELY(! stream))
//     {
//         bufferpoolResuesBuffer(getWorkerBufferPool(con->line), buf);
//         return;
//     }

//     if (con->content_type == kApplicationGrpc)
//     {
//         grpc_message_hd msghd;
//         msghd.flags  = 0;
//         msghd.length = sbufGetBufLength(buf);
//         flags        = kHttP2FlagNone;
//         sbufShiftLeft(buf, GRPC_MESSAGE_HDLEN);
//         grpcMessageHdPack(&msghd, sbufGetMutablePtr(buf));
//     }

//     http2_frame_hd framehd;
//     framehd.length    = sbufGetBufLength(buf);
//     framehd.type      = kHttP2Data;
//     framehd.flags     = flags;
//     framehd.stream_id = stream->stream_id;
//     sbufShiftLeft(buf, HTTP2_FRAME_HDLEN);
//     http2FrameHdPack(&framehd, sbufGetMutablePtr(buf));
//     context_t *data                = contextCreate(con->line);
//     data->payload                  = buf;
//     line_t *h2_line = data->line;
//     // make sure line is not freed, to be able to pause it
//     lineLock(stream->line);
//     con->current_stream_write_line = stream->line;
//     con->tunnel->up->upStream(con->tunnel->up, data);
//     lineUnlock(stream->line);
//     if (lineIsAlive(h2_line))
//     {
//         con->current_stream_write_line = NULL;
//     }
// }


// static void flushWriteQueue(httpclient_lstate_t *con)
// {
//     while (bufferqueueGetBufCount(&con->bq) > 0)
//     {
//         sbuf_t *buf = bufferqueuePopFront(&con->bq);
//         if (lineIsAlive(con->line)) // always true, since the stream is found before calling this
//         {
//             http2_client_child_con_state_t *stream = CSTATE(stream_context);

//             lineLock(stream->line);
//             action_queue_t_push(&con->actions, (http2_action_t) {.action_id   = kActionConData,
//                                                                  .stream_line = stream->line,
//                                                                  .buf         = stream_context->payload});
//         }

//         contextDropPayload(stream_context);
//         contextDestroy(stream_context);
//     }
// }

// int httpclientV2OnHeaderCallBack(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name,
//                                  size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *userdata)
// {
//     // (void) name;
//     (void) session;
//     (void) namelen;
//     (void) value;
//     (void) valuelen;
//     (void) flags;
//     (void) userdata;
//     (void) frame;
//     (void) name;

//     // Todo (http headers) should be saved somewhere
//     // if (*name == ':')
//     // {
//     //     if (strcmp(name, ":method") == 0)
//     //     {
//     //         // req->method = http_method_enum(value);
//     //     }
//     //     else if (strcmp(name, ":path") == 0)
//     //     {
//     //         // req->url = value;
//     //     }
//     //     else if (strcmp(name, ":scheme") == 0)
//     //     {
//     //         // req->headers["Scheme"] = value;
//     //     }
//     //     else if (strcmp(name, ":authority") == 0)
//     //     {
//     //         // req->headers["Host"] = value;
//     //     }
//     // }

//     return 0;
// }

// int httpclientV2OnDataChunkRecvCallBack(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data,
//                                         size_t len, void *userdata)
// {
//       (void) flags;
//     if (UNLIKELY(userdata == NULL || len <= 0))
//     {
//         return 0;
//     }
//     httpclient_lstate_t *con = (httpclient_lstate_t *) userdata;

//     http2_client_child_con_state_t *stream = nghttp2_session_get_stream_user_data(session, stream_id);

//     if (UNLIKELY(! stream))
//     {
//         return 0;
//     }

//     sbuf_t *buf = bufferpoolGetLargeBuffer(getWorkerBufferPool(lineGetWID(con->line)));
//     sbufSetLength(buf, len);
//     sbufWrite(buf, data, len);

//     contextqueuePush(&con->cq, contextCreatePayload(stream->line, buf));

//     // lineLock(stream->line);

//     // action_queue_t_push(
//     //     &con->actions,
//     //     (http2_action_t) {.action_id = kActionStreamDataReceived, .stream_line = stream->line, .buf = buf});

//     return 0;
// }

// int httpclientV2OnFrameRecvCallBack(nghttp2_session *session, const nghttp2_frame *frame, void *userdata)
// {
//     (void) session;
//     if (UNLIKELY(userdata == NULL))
//     {
//         return 0;
//     }

//     // LOGD("onFrameRecvCallBack\n");
//     printFrameHd(&frame->hd);
//     httpclient_lstate_t *con = (httpclient_lstate_t *) userdata;
//     // tunnel_t                 *self = con->tunnel;

//     switch (frame->hd.type)
//     {
//     case NGHTTP2_DATA:
//         break;
//     case NGHTTP2_HEADERS:
//         break;
//     case NGHTTP2_SETTINGS:
//         break;
//     case NGHTTP2_PING:
//         con->no_ping_ack = false;
//         break;
//     case NGHTTP2_RST_STREAM:
//     case NGHTTP2_WINDOW_UPDATE:
//         // ignore
//         return 0;
//     default:
//         break;
//     }

//     if ((frame->hd.type & NGHTTP2_HEADERS) == NGHTTP2_HEADERS)
//     {
//         if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) == NGHTTP2_FLAG_END_STREAM)
//         {
//             // LOGD("end stream for: %d", frame->hd.stream_id);

//             http2_client_child_con_state_t *stream = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
//             if (UNLIKELY(! stream))
//             {
//                 return 0;
//             }
//             lineLock(stream->line);
//             action_queue_t_push(
//                 &con->actions,
//                 (http2_action_t) {.action_id = kActionStreamFinish, .stream_line = stream->line, .buf = NULL});
//         }

//         if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE)
//         {
//             con->handshake_completed = true;

//             http2_client_child_con_state_t *stream =
//                 nghttp2_session_get_stream_user_data(con->session, frame->hd.stream_id);
//             if (stream)
//             {
//                 flushWriteQueue(con);

//                 contextqueuePush(&con->cq, contextCreateEst(stream->line));

//                 // lineLock(stream->line);
//                 // action_queue_t_push(
//                 //     &con->actions,
//                 //     (http2_action_t) {.action_id = kActionStreamEst, .stream_line = stream->line, .buf = NULL});
//             }
//         }
//     }

//     return 0;
// }

// int httpclientV2OnStreamClosedCallBack(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *userdata)
// {
//     (void) error_code;
//     (void) userdata;

//     httpclient_lstate_t       *con    = (httpclient_lstate_t *) userdata;
//     http2_client_child_con_state_t *stream = nghttp2_session_get_stream_user_data(session, stream_id);
//     // LOGD("callback end stream for: %d", stream_id);

//     // todo (optimize) nghttp2 is calling this callback even if we close the con ourselves
//     // this should be omitted

//     if (! stream)
//     {
//         return 0;
//     }
//     contextqueuePush(&con->cq, contextCreateFin(stream->line));
    
//     // lineLock(stream->line);
//     // action_queue_t_push(&con->actions,
//                         // (http2_action_t) {.action_id = kActionStreamFinish, .stream_line = stream->line, .buf = NULL});
// }
