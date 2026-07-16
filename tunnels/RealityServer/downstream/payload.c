#include "structure.h"

void realityserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    realityserver_lstate_t *ls = lineGetState(l, t);

    if (ls->closing_destination_for_authorized)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->terminal_closing || ls->prev_finished)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->mode == kRealityServerModeAuthorized)
    {
        realityserverEncryptAndSendDownstream(t, l, buf);
        return;
    }

    if (ls->mode == kRealityServerModePending)
    {
        buffer_pool_t *pool = lineGetBufferPool(l);
        lineLock(l);
        bool alive = realityserverObserveDownstreamHandshake(t, l, sbufGetRawPtr(buf), sbufGetLength(buf));
        if (! alive || ! lineIsAlive(l))
        {
            bufferpoolReuseBuffer(pool, buf);
            lineUnlock(l);
            return;
        }
        lineUnlock(l);
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}
