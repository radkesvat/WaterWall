#include "structure.h"

#include "loggers/network_logger.h"

void httpclientLinestateInitialize(httpclient_lstate_t *ls, tunnel_t *t, line_t *l)
{
    *ls = (httpclient_lstate_t) {.tunnel               = t,
                                 .line                 = l,
                                 .session              = NULL,
                                 .in_stream            = bufferstreamCreate(lineGetBufferPool(l), 0),
                                 .pending_up           = bufferqueueCreate(kHttpClientBufferQueueCap),
                                 .events_down          = contextqueueCreate(),
                                 .h2_data_head         = NULL,
                                 .h2_data_tail         = NULL,
                                 .h2_data_active       = NULL,
                                 .runtime_proto        = kHttpClientRuntimeUnknown,
                                 .h2_stream_id         = 0,
                                 .h1_chunk_expected    = -1,
                                 .h1_body_remaining    = 0,
                                 .h1_headers_parsed    = false,
                                 .h1_response_chunked  = false,
                                 .h1_upgrade_accepted  = false,
                                 .h1_body_mode         = kHttpClientH1BodyNone,
                                 .h2_headers_received  = false,
                                 .response_complete    = false,
                                 .prev_finished        = false,
                                 .next_finished        = false,
                                 .fin_sent             = false,
                                 .websocket_active             = false,
                                 .websocket_waiting_handshake  = false,
                                 .websocket_close_sent         = false,
                                 .websocket_close_received     = false,
                                 .websocket_h2_waiting_connect = false,
                                 .websocket_h2_request_submitted = false,
                                 .websocket_h2_status_seen       = false,
                                 .websocket_h2_protocol_seen     = false,
                                 .websocket_h2_extensions_seen   = false,
                                 .websocket_h2_status_code       = 0,
                                 .split_role                     = kHttpClientSplitRoleNone,
                                 .split_main_line                = NULL,
                                 .split_upload_line              = NULL,
                                 .split_download_line            = NULL};
}

static void httpclientLinestateH2DataItemDestroy(line_t *line, httpclient_h2_data_item_t *item)
{
    if (item == NULL)
    {
        return;
    }
    if (item->payload != NULL)
    {
        lineReuseBuffer(line, item->payload);
    }
    memoryFree(item);
}

void httpclientH2DataQueueDestroy(httpclient_lstate_t *ls)
{
    httpclientLinestateH2DataItemDestroy(ls->line, ls->h2_data_active);
    ls->h2_data_active = NULL;

    httpclient_h2_data_item_t *item = ls->h2_data_head;
    while (item != NULL)
    {
        httpclient_h2_data_item_t *next = item->next;
        httpclientLinestateH2DataItemDestroy(ls->line, item);
        item = next;
    }

    ls->h2_data_head = NULL;
    ls->h2_data_tail = NULL;
}

void httpclientLinestateDestroy(httpclient_lstate_t *ls)
{
    if (ls->session != NULL)
    {
        nghttp2_session_del(ls->session);
        ls->session = NULL;
    }

    httpclientH2DataQueueDestroy(ls);
    bufferstreamDestroy(&ls->in_stream);
    bufferqueueDestroy(&ls->pending_up);
    contextqueueDestroy(&ls->events_down);

    memoryZeroAligned32(ls, sizeof(*ls));
}
