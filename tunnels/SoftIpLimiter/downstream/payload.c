#include "structure.h"

void softiplimiterTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    softiplimiter_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->closing || ls->phase != kSoftIpLimiterPhaseEstablished))
    {
        lineReuseBuffer(l, buf);
        if (! ls->closing)
        {
            softiplimiterCloseLine(t, l, kSoftIpLimiterCloseFromNext);
        }
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

    tunnelPrevDownStreamPayload(t, l, buf);
}

