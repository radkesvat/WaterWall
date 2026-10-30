#include "structure.h"

#include "loggers/network_logger.h"

void httpserverLinestateInitialize(httpserver_lstate_t *ls, tunnel_t *t, line_t *l)
{
    *ls = (httpserver_lstate_t) {.tunnel                        = t,
                                 .line                          = l,
                                 .session                       = NULL,
                                 .in_stream                     = bufferstreamCreate(lineGetBufferPool(l), 0),
                                 .pending_down                  = bufferqueueCreate(kHttpServerBufferQueueCap),
                                 .split_pending_up              = bufferqueueCreate(kHttpServerBufferQueueCap),
                                 .events_up                     = contextqueueCreate(),
                                 .runtime_proto                 = kHttpServerRuntimeUnknown,
                                 .h2_stream_id                  = 0,
                                 .h1_body_remaining             = 0,
                                 .h1_headers_parsed             = false,
                                 .h1_request_finished           = false,
                                 .h1_trailing_bytes_logged      = false,
                                 .h1_response_headers_sent      = false,
                                 .h1_body_mode                  = kHttpServerH1BodyNone,
                                 .h2_response_headers_sent      = false,
                                 .h2_request_finished           = false,
                                 .h2_request_rejected           = false,
                                 .fin_sent                      = false,
                                 .prev_finished                 = false,
                                 .next_finished                 = false,
                                 .websocket_active              = false,
                                 .websocket_close_sent          = false,
                                 .websocket_close_received      = false,
                                 .websocket_h2_method_seen      = false,
                                 .websocket_h2_protocol_seen    = false,
                                 .websocket_h2_path_seen        = false,
                                 .websocket_h2_authority_seen   = false,
                                 .websocket_h2_version_seen     = false,
                                 .websocket_h2_subprotocol_seen = false,
                                 .websocket_h2_origin_seen      = false,
                                 .split_role                    = kHttpServerSplitRoleNone,
                                 .split_main_line               = NULL,
                                 .split_upload_line             = NULL,
                                 .split_download_line           = NULL,
                                 .split_hash                    = 0};
    httpReceiveInit(&ls->receive);
    h2DataInit(&ls->h2_data, lineGetBufferPool(l), UINT32_MAX);
}

void httpserverLinestateDestroy(httpserver_lstate_t *ls)
{
    if (ls->session != NULL)
    {
        nghttp2_session_del(ls->session);
        ls->session = NULL;
    }

    h2DataDestroyAfterSession(&ls->h2_data);
    httpReceiveDestroy(&ls->receive, ls->in_stream.pool);
    bufferstreamDestroy(&ls->in_stream);
    bufferqueueDestroy(&ls->pending_down);
    bufferqueueDestroy(&ls->split_pending_up);
    contextqueueDestroy(&ls->events_up);

    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
