#include "structure.h"

void realityserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    realityserver_lstate_t *ls = lineGetState(l, t);

    if (ls->prev_finished || ls->closing_destination_for_authorized)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->mode == kRealityServerModeAuthorized)
    {
        realityserverEncryptAndSendDownstream(t, l, buf);
        return;
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}
