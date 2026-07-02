#include "structure.h"

static void routerBufferPendingPayload(line_t *l, router_lstate_t *ls, sbuf_t *buf)
{
    if (ls->pending == NULL)
    {
        ls->pending = buf;
        return;
    }

    uint32_t need = sbufGetLength(ls->pending) + sbufGetLength(buf);
    ls->pending   = sbufReserveSpace(ls->pending, need);
    sbufConcatNoCheck(ls->pending, buf);
    lineReuseBuffer(l, buf);
}

static void routerForwardPayload(tunnel_t *t, line_t *l, router_lstate_t *ls, sbuf_t *buf)
{
    if (ls->route == kRouterRouteTarget)
    {
        tunnelUpStreamPayload(ls->target, l, buf);
        return;
    }

    tunnelNextUpStreamPayload(t, l, buf);
}

static void routerCommitRoute(tunnel_t *t, line_t *l, router_lstate_t *ls, tunnel_t *target, sbuf_t *first)
{
    lineLock(l);

    if (target != NULL)
    {
        ls->target  = target;
        ls->route   = kRouterRouteTarget;
        tunnelUpStreamInit(target, l);
        if (lineIsAlive(l))
        {
            tunnelUpStreamPayload(target, l, first);
            first = NULL;
        }
    }
    else
    {
        ls->target  = NULL;
        ls->route   = kRouterRouteDefault;
        tunnelNextUpStreamInit(t, l);
        if (lineIsAlive(l))
        {
            tunnelNextUpStreamPayload(t, l, first);
            first = NULL;
        }
    }

    if (first != NULL)
    {
        lineReuseBuffer(l, first);
    }

    lineUnlock(l);
}

void routerTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    router_tstate_t *ts = tunnelGetState(t);
    router_lstate_t *ls = lineGetState(l, t);

    if (ls->route != kRouterRouteUndecided)
    {
        routerForwardPayload(t, l, ls, buf);
        return;
    }

    routerBufferPendingPayload(l, ls, buf);

    router_match_ctx_t mctx = {
        .router_state = ts,
        .line         = l,
        .line_state   = ls,
        .payload      = (const uint8_t *) sbufGetRawPtr(ls->pending),
        .payload_len  = sbufGetLength(ls->pending),
    };

    router_match_t match = routerClassify(ts, &mctx);
    if (match.result == kRouterClassifyNeedMore)
    {
        // A future content-based matcher may ask for more bytes; keep buffering.
        return;
    }

    sbuf_t *first = ls->pending;
    ls->pending   = NULL;

    routerCommitRoute(t, l, ls, match.result == kRouterClassifyTarget ? match.target : NULL, first);
}
