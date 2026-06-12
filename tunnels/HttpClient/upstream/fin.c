#include "structure.h"

#include "loggers/network_logger.h"

void httpclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    httpclient_lstate_t *ls = lineGetState(l, t);
    httpclient_tstate_t *ts = tunnelGetState(t);

    if (ls->split_role == kHttpClientSplitRoleMain)
    {
        httpclientSplitUpStreamFinish(t, l);
        return;
    }

    lineLock(l);

    ls->prev_finished = true;

    if (ts->websocket_enabled && ls->websocket_active)
    {
        if (! httpclientTransportSendWebSocketClose(t, l, ls))
        {
            if (lineIsAlive(l))
            {
                httpclientTransportCloseNextDirection(t, l, ls);
            }
            lineUnlock(l);
            return;
        }

        if (ls->runtime_proto == kHttpClientRuntimeHttp2 && ! ls->fin_sent && ! ls->next_finished)
        {
            ls->fin_sent = true;
            if (! httpclientTransportSendHttp2DataFrame(t, l, ls, NULL, true))
            {
                if (lineIsAlive(l))
                {
                    httpclientTransportCloseNextDirection(t, l, ls);
                }
                lineUnlock(l);
                return;
            }
        }
    }

    if (! ts->websocket_enabled && ls->runtime_proto == kHttpClientRuntimeHttp1)
    {
        if (! ls->fin_sent)
        {
            ls->fin_sent = true;
            if (! httpclientTransportSendHttp1FinalChunk(t, l))
            {
                if (lineIsAlive(l))
                {
                    httpclientTransportCloseNextDirection(t, l, ls);
                }
                lineUnlock(l);
                return;
            }
        }
    }
    else if (! ts->websocket_enabled && ls->runtime_proto == kHttpClientRuntimeHttp2)
    {
        if (! ls->fin_sent)
        {
            ls->fin_sent = true;
            if (! httpclientTransportSendHttp2DataFrame(t, l, ls, NULL, true))
            {
                if (lineIsAlive(l))
                {
                    httpclientTransportCloseNextDirection(t, l, ls);
                }
                lineUnlock(l);
                return;
            }
        }
    }
    else
    {
        ls->fin_sent = true;
    }

    // Sending the final bytes above can re-enter this tunnel through a downstream Finish
    // (e.g. the next adapter overflows its write queue and finishes us back). In that case
    // next is already finished and must not receive another Finish; we still own the
    // line-state destruction because the re-entrant downStreamFinish bailed out on
    // prev_finished without touching the state.
    bool next_finished = ls->next_finished;

    httpclientLinestateDestroy(ls);
    if (! next_finished)
    {
        tunnelNextUpStreamFinish(t, l);
    }
    lineUnlock(l);
}
