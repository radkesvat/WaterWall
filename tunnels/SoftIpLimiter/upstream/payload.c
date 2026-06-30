#include "structure.h"

void softiplimiterTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    softiplimiter_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->closing || ls->phase == kSoftIpLimiterPhaseClosing))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->phase != kSoftIpLimiterPhaseEstablished)
    {
        softiplimiterHandleInitialPayload(t, l, buf);
        return;
    }

    softiplimiter_table_result_t result = {0};
    if (UNLIKELY(! softiplimiterTouchLine(t, ls, softiplimiterNowMs(), &result)))
    {
        lineReuseBuffer(l, buf);
        softiplimiterLogActiveClose(t, l, ls, NULL, &result);
        softiplimiterCloseLine(t, l, kSoftIpLimiterCloseInternal);
        return;
    }

    tunnelNextUpStreamPayload(t, l, buf);
}

