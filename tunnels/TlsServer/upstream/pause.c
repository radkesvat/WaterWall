#include "structure.h"

void tlsserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    tlsserver_tstate_t *ts = tunnelGetState(t);
    tlsserver_lstate_t *ls = lineGetState(l, t);

    if (ls->fallback_close_draining || ls->upstream_finished || ls->downstream_finishing)
    {
        return;
    }

    if (ls->fallback_mode)
    {
        ls->pending_branch_pause = false;
        tunnelUpStreamPause(ts->fallback_tunnel, l);
        return;
    }

    if (! ls->protected_init_sent)
    {
        ls->pending_branch_pause = true;
        return;
    }

    ls->pending_branch_pause = false;
    tunnelNextUpStreamPause(t, l);
}
