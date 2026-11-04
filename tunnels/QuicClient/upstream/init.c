#include "structure.h"

void quicclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    quic_context_t *context = quicBeginLineInit(t, l);
    if (context == NULL)
    {
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    /* The new next-side line has independent ownership from the caller. */
    line_t *next = quicNextLine(context);
    lineRef(next);
    tunnelNextUpStreamInit(t, next);
    lineUnref(next);
    quicCompleteLineInit(context);
}
