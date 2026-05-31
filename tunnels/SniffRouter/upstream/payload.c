#include "structure.h"

void sniffrouterTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    sniffrouter_tstate_t *ts = tunnelGetState(t);
    sniffrouter_lstate_t *ls = lineGetState(l, t);

    if (ls->prev_finished || ls->next_finished)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->decided == kSniffRouteWeb)
    {
        tunnelUpStreamPayload(ts->web_tunnel, l, buf);
        return;
    }
    if (ls->decided == kSniffRouteTunnel)
    {
        tunnelNextUpStreamPayload(t, l, buf);
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

    int verdict = sniffrouterClassify(p, n);

    if (verdict < 0 && n < (uint32_t) kSniffDecideBytes)
    {
        return;
    }

    sbuf_t *first = ls->pending;
    ls->pending   = NULL;

    lineLock(l);

    if (verdict == 1)
    {
        ls->decided = kSniffRouteWeb;
        tunnelUpStreamInit(ts->web_tunnel, l);
        if (lineIsAlive(l))
        {
            tunnelUpStreamPayload(ts->web_tunnel, l, first);
            first = NULL;
        }
    }
    else
    {
        ls->decided = kSniffRouteTunnel;
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
