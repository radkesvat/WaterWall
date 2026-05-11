#include "structure.h"

#include "loggers/network_logger.h"

void httpclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    httpclient_lstate_t *ls = lineGetState(l, t);
    httpclient_tstate_t *ts = tunnelGetState(t);

    if (ls->split_role == kHttpClientSplitRoleUpload || ls->split_role == kHttpClientSplitRoleDownload)
    {
        httpclientSplitDownStreamFinish(t, l);
        return;
    }

    lineLock(l);

    ls->next_finished = true;

    if (! ts->websocket_enabled && ! ls->prev_finished)
    {
        bool truncated = false;

        if (ls->runtime_proto == kHttpClientRuntimeHttp1)
        {
            if (! ls->h1_headers_parsed)
            {
                truncated = true;
            }
            else if (ls->h1_body_mode == kHttpClientH1BodyContentLen && ls->h1_body_remaining != 0)
            {
                truncated = true;
            }
            else if (ls->h1_body_mode == kHttpClientH1BodyChunked && ! ls->response_complete)
            {
                truncated = true;
            }
        }
        else if (ls->runtime_proto == kHttpClientRuntimeHttp2 && ! ls->response_complete)
        {
            truncated = true;
        }

        if (truncated)
        {
            LOGE("HttpClient: response stream ended before the HTTP body was complete");
        }
    }

    httpclientLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
    lineUnlock(l);
}
