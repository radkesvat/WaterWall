#include "structure.h"

#include "loggers/network_logger.h"

static bool flushPendingUpstream(tunnel_t *t, line_t *l, realityclient_lstate_t *ls)
{
    while (bufferqueueGetBufCount(&ls->pending_up) > 0)
    {
        sbuf_t *buf = bufferqueuePopFront(&ls->pending_up);
        if (! realityclientEncryptAndSend(t, l, buf))
        {
            return false;
        }
        if (! lineIsAlive(l))
        {
            return false;
        }
    }

    return true;
}

void realityclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    realityclient_tstate_t *ts = tunnelGetState(t);
    sbuf_t                 *pending_raw = NULL;

    lineLock(l);

    realityclient_lstate_t *ls = lineGetState(l, t);
    if (! tlsclientTunnelIsHandshakeCompleted(ts->tls_tunnel, l) ||
        ! tlsclientTunnelDeinitAfterHandshake(ts->tls_tunnel, l, &pending_raw))
    {
        LOGW("RealityClient: internal TLS handshake takeover failed");
        if (pending_raw != NULL)
        {
            lineReuseBuffer(l, pending_raw);
        }
        lineUnlock(l);
        realityclientCloseLineBidirectional(t, l);
        return;
    }

    ls->tls_ready = true;

    if (! flushPendingUpstream(t, l, ls))
    {
        if (pending_raw != NULL)
        {
            lineReuseBuffer(l, pending_raw);
        }
        lineUnlock(l);
        return;
    }

    if (! lineIsAlive(l))
    {
        if (pending_raw != NULL)
        {
            lineReuseBuffer(l, pending_raw);
        }
        lineUnlock(l);
        return;
    }

    tunnelPrevDownStreamEst(t, l);
    if (! lineIsAlive(l))
    {
        if (pending_raw != NULL)
        {
            lineReuseBuffer(l, pending_raw);
        }
        lineUnlock(l);
        return;
    }

    if (pending_raw != NULL)
    {
        realityclientProcessDownstream(t, l, pending_raw);
    }

    lineUnlock(l);
}
