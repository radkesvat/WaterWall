#include "structure.h"

void tlsserverTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    tlsserver_tstate_t *ts = tunnelGetState(t);
    tlsserver_lstate_t *ls = lineGetState(l, t);

    if (ls->fallback_close_draining || ls->upstream_finished || ls->downstream_finishing)
    {
        return;
    }
    ls->prev_paused = false;

    if (ls->fallback_mode)
    {
        ls->pending_branch_pause = false;
        tunnelUpStreamResume(ts->fallback_tunnel, l);
        return;
    }

    if (! ls->protected_init_sent)
    {
        ls->pending_branch_pause = false;
        return;
    }

    ls->pending_branch_pause = false;
    if (ls->shaping_producer_paused)
    {
        return;
    }
    tunnelNextUpStreamResume(t, l);
}
