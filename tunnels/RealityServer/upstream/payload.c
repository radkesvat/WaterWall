#include "structure.h"

void realityserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    realityserver_tstate_t *ts = tunnelGetState(t);
    realityserver_lstate_t *ls = lineGetState(l, t);

    if (ls->mode == kRealityServerModeVisitor)
    {
        withLineLockedWithBuf(l, tunnelUpStreamPayload, ts->destination_tunnel, buf);
        return;
    }

    realityserverProcessUpstream(t, l, buf);
}
