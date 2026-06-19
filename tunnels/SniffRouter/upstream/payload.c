#include "structure.h"

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
    lineLock(l);

    if (target != NULL)
    {
        ls->target  = target;
        ls->decided = kSniffRouteTarget;
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
        ls->decided = kSniffRouteDefault;
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

void sniffrouterTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    sniffrouter_tstate_t *ts = tunnelGetState(t);
    sniffrouter_lstate_t *ls = lineGetState(l, t);

    if (ls->decided != kSniffRouteUndecided)
    {
        forwardSelectedPayload(t, l, ls, buf);
        return;
    }

    if (ls->pending == NULL)
    {
        ls->pending = buf;
    }
    else
    {
        uint32_t need = sbufGetLength(ls->pending) + sbufGetLength(buf);
        ls->pending   = sbufReserveSpace(ls->pending, need);
        sbufConcatNoCheck(ls->pending, buf);
        lineReuseBuffer(l, buf);
    }

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
