#include "structure.h"

#include "loggers/network_logger.h"

enum
{
    kRouterPendingBytes   = 2U * 1024U * 1024U,
    kRouterDatagramCharge = 4U * 1024U * 1024U,
    kRouterDatagramCount  = 1024U
};

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

static void routerRejectPendingPayload(tunnel_t *t, line_t *l, router_lstate_t *ls, sbuf_t *buf)
{
    const uint8_t route  = ls->route;
    tunnel_t     *target = ls->target;
    lineRef(l);
    lineReuseBuffer(l, buf);
    routerLinestateDestroy(l, ls);
    if (route == kRouterRouteTarget)
        tunnelUpStreamFin(target, l);
    else if (route == kRouterRouteDefault)
        tunnelNextUpStreamFinish(t, l);
    if (lineIsAlive(l))
        tunnelPrevDownStreamFinish(t, l);
    lineUnref(l);
}

static bool routerQueueDatagram(tunnel_t *t, line_t *l, router_lstate_t *ls, sbuf_t **buf)
{
    const size_t bytes  = sbufGetLength(*buf);
    const size_t charge = sbufGetQueueCharge(*buf);
    if (bytes > kRouterPendingBytes || bufferqueueGetBufLen(&ls->datagrams) > kRouterPendingBytes - bytes ||
        charge > kRouterDatagramCharge || bufferqueueGetCharge(&ls->datagrams) > kRouterDatagramCharge - charge ||
        bufferqueueGetBufCount(&ls->datagrams) >= kRouterDatagramCount)
    {
        LOGE("Router: pending datagrams exceeded their retention limit, closing this line");
        routerRejectPendingPayload(t, l, ls, *buf);
        return false;
    }
    *buf = bufferqueuePushBack(&ls->datagrams, *buf);
    return true;
}

static void routerAppendDatagramSniffView(router_lstate_t *ls, const sbuf_t *buf)
{
    // The queue owns buf. Copy only the inspection view; replay uses the original entries.
    const uint32_t length     = sbufGetLength(buf);
    const uint32_t old_length = ls->pending != NULL ? sbufGetLength(ls->pending) : 0;
    const uint32_t total      = old_length + length; // bounded by datagram queue admission
    if (ls->pending == NULL)
        ls->pending = sbufCreateWithPadding(total, 0);
    else
        ls->pending = sbufReserveSpace(ls->pending, total);
    sbufConcatNoCheck(ls->pending, buf);
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

    if (lineIsAlive(l) && ls->replaying && ls->pending_pause)
    {
        // Keep startup input queued until this notification returns, including reentry.
        routerTunnelUpStreamPause(t, l);
    }

    // Keep the accepted first delivery ahead of input submitted from Init/Est.
    // Reentry joins the pending FIFO until Init and every startup handoff return.
    while (lineIsAlive(l) && ls->replaying)
    {
        if (first == NULL)
        {
            if (ls->datagram_input)
                first = bufferqueuePopFront(&ls->datagrams);
            else
            {
                first       = ls->pending;
                ls->pending = NULL;
            }
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
    if (ls->datagram_input)
    {
        discard routerQueueDatagram(t, l, ls, &buf);
        return;
    }
    const uint32_t limit    = kRouterPendingBytes;
    const uint32_t queued   = ls->pending != NULL ? sbufGetLength(ls->pending) : 0;
    const uint32_t incoming = sbufGetLength(buf);
    if (incoming > limit || queued > limit - incoming)
    {
        LOGE("Router: initial replay backlog exceeded its limit, closing this line");
        routerRejectPendingPayload(t, l, ls, buf);
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

    if (ls->datagram_input)
    {
        if (! routerQueueDatagram(t, l, ls, &buf))
            return;
        routerAppendDatagramSniffView(ls, buf);
    }
    else
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
        // Keep incomplete protocol metadata for the next delivery.
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
    if (ls->datagram_input)
    {
        lineReuseBuffer(l, first);
        first = NULL;
    }

    routerCommitRoute(t, l, ls, match.result == kRouterClassifyTarget ? match.target : NULL, first);
}
