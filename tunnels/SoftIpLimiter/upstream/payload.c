#include "structure.h"

void softiplimiterTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    softiplimiter_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->closing || ls->phase == kSoftIpLimiterPhaseClosing))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (! softiplimiterPhaseForwards(ls->phase))
    {
        softiplimiterHandleInitialPayload(t, l, buf);
        return;
    }

    if (ls->phase == kSoftIpLimiterPhaseEstablished)
    {
        softiplimiter_table_result_t result = {0};
        if (UNLIKELY(! softiplimiterTouchLine(t, ls, softiplimiterNowMs(), &result)))
        {
            lineReuseBuffer(l, buf);
            softiplimiterLogActiveClose(t, l, ls, NULL, &result);
            softiplimiterCloseLine(t, l, kSoftIpLimiterCloseInternal);
            return;
        }
    }
    switch (nextinitgateSubmit(&ls->gate, &buf))
    {
    case kNextInitGateQueued:
        return;
    case kNextInitGateRejected:
        lineReuseBuffer(l, buf);
        softiplimiterCloseLine(t, l, kSoftIpLimiterCloseInternal);
        return;
    case kNextInitGateForward:
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }
}
