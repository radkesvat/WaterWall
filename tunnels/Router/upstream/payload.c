#include "structure.h"

#include "loggers/network_logger.h"

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

void routerCommitRoute(tunnel_t *t, line_t *l, router_lstate_t *ls, tunnel_t *target, sbuf_t *first)
{
    lineRef(l);

    ls->target    = target;
    ls->route     = target != NULL ? kRouterRouteTarget : kRouterRouteDefault;
    ls->replaying = true;
    if (target != NULL)
    {
        tunnelUpStreamInit(target, l);
    }
    else
    {
        tunnelNextUpStreamInit(t, l);
    }

    // Keep the accepted first delivery ahead of input submitted from Init/Est.
    // Reentry appends to pending until Init and every startup handoff return.
    while (lineIsAlive(l) && ls->replaying)
    {
        if (first == NULL)
        {
            first       = ls->pending;
            ls->pending = NULL;
        }
        if (first == NULL)
        {
            ls->replaying = false;
            if (target == NULL || target == t->next)
            {
                routerLinestateDestroy(l, ls);
                tunnelBypassLine(t, l);
            }
            break;
        }

        sbuf_t *out = first;
        first       = NULL;
        routerForwardPayload(t, l, ls, out);
    }

    if (first != NULL)
    {
        lineReuseBuffer(l, first);
    }

    lineUnref(l);
}

static void routerBufferReentrantPayload(tunnel_t *t, line_t *l, router_lstate_t *ls, sbuf_t *buf)
{
    const uint32_t limit    = 2U * 1024U * 1024U;
    const uint32_t queued   = ls->pending != NULL ? sbufGetLength(ls->pending) : 0;
    const uint32_t incoming = sbufGetLength(buf);
    if (incoming > limit || queued > limit - incoming)
    {
        LOGE("Router: initial replay backlog exceeded its limit, closing this line");
        // The selected branch has received Init. Settle both directions while
        // the outer commit keeps its first delivery and line reference alive.
        tunnel_t *target = ls->target;
        lineRef(l);
        lineReuseBuffer(l, buf);
        routerLinestateDestroy(l, ls);
        if (target != NULL)
        {
            tunnelUpStreamFin(target, l);
        }
        else
        {
            tunnelNextUpStreamFinish(t, l);
        }
        if (lineIsAlive(l))
        {
            tunnelPrevDownStreamFinish(t, l);
        }
        lineUnref(l);
        return;
    }

    buf = sbufEnsureOrdinary(lineGetBufferPool(l), buf);
    routerBufferPendingPayload(l, ls, buf);
}

void routerTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    router_tstate_t *ts = tunnelGetState(t);
    router_lstate_t *ls = lineGetState(l, t);

    if (ls->route != kRouterRouteUndecided)
    {
        if (ls->replaying)
        {
            routerBufferReentrantPayload(t, l, ls, buf);
            return;
        }
        routerForwardPayload(t, l, ls, buf);
        return;
    }

    // Sniffing and pending storage use ordinary memory until the route is committed.
    buf = sbufEnsureOrdinary(lineGetBufferPool(l), buf);

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

    if (match.result == kRouterClassifyError)
    {
        // No route was committed, so the selected/default branch never received Init and only the previous side
        // may be closed. routerLinestateDestroy() recycles the pending payload.
        LOGE("Router: rule evaluation failed at runtime, closing this line");
        routerLinestateDestroy(l, ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    sbuf_t *first = ls->pending;
    ls->pending   = NULL;

    routerCommitRoute(t, l, ls, match.result == kRouterClassifyTarget ? match.target : NULL, first);
}
