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

static void closeSelectedRoute(tunnel_t *t, line_t *l, sniffrouter_lstate_t *ls)
{
    tunnel_t *target = ls->decided == kSniffRouteTarget ? ls->target : t->next;

    lineRef(l);
    sniffrouterLinestateDestroy(l, ls);
    tunnelUpStreamFin(target, l);
    if (lineIsAlive(l))
    {
        tunnelPrevDownStreamFinish(t, l);
    }
    lineUnref(l);
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
        forwardSelectedPayload(t, l, ls, first);
        first = NULL;
        if (! lineIsAlive(l) || ! ls->replaying)
        {
            break;
        }

        first       = ls->pending;
        ls->pending = NULL;
        if (first == NULL)
        {
            if (ls->decided == kSniffRouteDefault)
            {
                sniffrouterLinestateDestroy(l, ls);
                tunnelBypassLine(t, l);
            }
            else
            {
                ls->replaying = false;
            }
            break;
        }
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
            uint32_t pending_len = ls->pending != NULL ? sbufGetLength(ls->pending) : 0;
            if (sbufGetLength(buf) > kSniffRouterMaxReplayBytes - pending_len)
            {
                LOGE("SniffRouter: initial replay backlog exceeded its limit, closing this line");
                lineReuseBuffer(l, buf);
                closeSelectedRoute(t, l, ls);
                return;
            }
            bufferPendingPayload(l, ls, buf);
            return;
        }
        forwardSelectedPayload(t, l, ls, buf);
        return;
    }

    // Sniffing and pending storage use ordinary memory until the route is committed.
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

    initializeSelectedRoute(t, l, ls, match.result == kSniffClassifyTarget ? match.target : NULL, first);
}
