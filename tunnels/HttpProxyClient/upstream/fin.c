#include "structure.h"
void httpproxyclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    hpc_lstate_t *ls       = lineGetState(l, t);
    hpc_tstate_t *ts       = tunnelGetState(t);
    bool          terminal = ! (ls->accepted && ls->body.kind == kHpsBodyDone) && ! ts->connect &&
                    ts->upload == kHpcBodyChunked && ls->header_sent && ! ls->init_busy && ! ls->up_busy &&
                    ! ls->suffix && ! bufferqueueGetBufCount(&ls->pending[0]) && ! ls->next_paused && hpcAllowed(t, l);
    if (! terminal)
    {
        bool next_init = ls->next_init;
        hpcDestroyState(t, l);
        if (next_init)
            tunnelNextUpStreamFinish(t, l);
        return;
    }
    ls->prev_finished = true;
    lineRef(l);
    sbuf_t *last = hpcBuffer(l, 5);
    if (last)
    {
        memoryCopy(sbufGetMutablePtr(last), "0\r\n\r\n", 5);
        sbufSetLength(last, 5);
        tunnelNextUpStreamPayload(t, l, last);
    }
    if (lineIsAlive(l))
    {
        bool next_finished = ls->next_finished;
        hpcDestroyState(t, l);
        if (! next_finished)
            tunnelNextUpStreamFinish(t, l);
    }
    lineUnref(l);
}
