#include "structure.h"

#include "loggers/network_logger.h"

static void bufferPendingPayload(line_t *l, sniffrouter_lstate_t *ls, sbuf_t *buf)
{
    buf = sbufEnsureOrdinary(lineGetBufferPool(l), buf);

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

static void closePendingRoute(tunnel_t *t, line_t *l, sniffrouter_lstate_t *ls)
{
    const uint8_t decided = ls->decided;
    tunnel_t     *target  = ls->decided == kSniffRouteTarget ? ls->target : t->next;

    lineRef(l);
    sniffrouterLinestateDestroy(l, ls);
    if (decided != kSniffRouteUndecided)
        tunnelUpStreamFin(target, l);
    if (lineIsAlive(l))
    {
        tunnelPrevDownStreamFinish(t, l);
    }
    lineUnref(l);
}

static bool queueDatagram(tunnel_t *t, line_t *l, sniffrouter_lstate_t *ls, sbuf_t **buf)
{
    const size_t bytes  = sbufGetLength(*buf);
    const size_t charge = sbufGetQueueCharge(*buf);
    if (bytes > kSniffRouterMaxReplayBytes ||
        bufferqueueGetBufLen(&ls->datagrams) > kSniffRouterMaxReplayBytes - bytes ||
        charge > kSniffRouterMaxDatagramCharge ||
        bufferqueueGetCharge(&ls->datagrams) > kSniffRouterMaxDatagramCharge - charge ||
        bufferqueueGetBufCount(&ls->datagrams) >= kSniffRouterMaxDatagrams)
    {
        LOGE("SniffRouter: pending datagrams exceeded their retention limit, closing this line");
        lineReuseBuffer(l, *buf);
        closePendingRoute(t, l, ls);
        return false;
    }
    *buf = bufferqueuePushBack(&ls->datagrams, *buf);
    return true;
}

static void appendDatagramSniffView(sniffrouter_lstate_t *ls, const sbuf_t *buf)
{
    // Replay retains each queue entry; only the inspection view joins their bytes.
    const uint32_t length     = sbufGetLength(buf);
    const uint32_t old_length = ls->pending != NULL ? sbufGetLength(ls->pending) : 0;
    const uint32_t total      = old_length + length; // bounded by datagram queue admission
    if (ls->pending == NULL)
        ls->pending = sbufCreateWithPadding(total, 0);
    else
        ls->pending = sbufReserveSpace(ls->pending, total);
    sbufConcatNoCheck(ls->pending, buf);
}

static void forwardSelectedPayload(tunnel_t *t, line_t *l, sniffrouter_lstate_t *ls, sbuf_t *buf)
{
    if (ls->decided == kSniffRouteTarget)
    {
        tunnelUpStreamPayload(ls->target, l, buf);
        return;
    }

    tunnelNextUpStreamPayload(t, l, buf);
}

static void initializeSelectedRoute(tunnel_t *t, line_t *l, sniffrouter_lstate_t *ls, tunnel_t *target, sbuf_t *first)
{
    lineRef(l);

    ls->replaying = true;
    if (target != NULL)
    {
        ls->target  = target;
        ls->decided = kSniffRouteTarget;
        tunnelUpStreamInit(target, l);
    }
    else
    {
        ls->target  = NULL;
        ls->decided = kSniffRouteDefault;
        tunnelNextUpStreamInit(t, l);
    }

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
            if (ls->decided == kSniffRouteDefault)
            {
                sniffrouterLinestateDestroy(l, ls);
                tunnelBypassLine(t, l);
            }
            break;
        }

        sbuf_t *out = first;
        first       = NULL;
        forwardSelectedPayload(t, l, ls, out);
    }

    if (first != NULL)
    {
        lineReuseBuffer(l, first);
    }
    lineUnref(l);
}

void sniffrouterTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    sniffrouter_tstate_t *ts = tunnelGetState(t);
    sniffrouter_lstate_t *ls = lineGetState(l, t);

    if (ls->decided != kSniffRouteUndecided)
    {
        if (ls->replaying)
        {
            if (ls->datagram_input)
            {
                discard queueDatagram(t, l, ls, &buf);
                return;
            }
            uint32_t pending_len = ls->pending != NULL ? sbufGetLength(ls->pending) : 0;
            if (sbufGetLength(buf) > kSniffRouterMaxReplayBytes - pending_len)
            {
                LOGE("SniffRouter: initial replay backlog exceeded its limit, closing this line");
                lineReuseBuffer(l, buf);
                closePendingRoute(t, l, ls);
                return;
            }
            bufferPendingPayload(l, ls, buf);
            return;
        }
        forwardSelectedPayload(t, l, ls, buf);
        return;
    }

    // Sniffing and pending storage use ordinary memory until the route is committed.
    if (ls->datagram_input)
    {
        buf = sbufEnsureOrdinary(lineGetBufferPool(l), buf);
        if (! queueDatagram(t, l, ls, &buf))
            return;
        appendDatagramSniffView(ls, buf);
    }
    else
        bufferPendingPayload(l, ls, buf);

    const uint8_t *p = (const uint8_t *) sbufGetRawPtr(ls->pending);
    uint32_t       n = sbufGetLength(ls->pending);

    sniffrouter_match_t match = sniffrouterClassify(ts, p, n);
    if (match.result == kSniffClassifyNeedMore)
    {
        return;
    }

    sbuf_t *first = ls->pending;
    ls->pending   = NULL;
    if (ls->datagram_input)
    {
        lineReuseBuffer(l, first);
        first = NULL;
    }

    initializeSelectedRoute(t, l, ls, match.result == kSniffClassifyTarget ? match.target : NULL, first);
}
