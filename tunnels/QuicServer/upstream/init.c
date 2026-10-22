#include "structure.h"

void quicserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    quic_context_t *context = quicBeginLineInit(t, l);
    if (context == NULL)
    {
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    /* The shared driver holds the borrowed line across reentrant Init delivery. */
    tunnelNextUpStreamInit(t, l);
    quicCompleteLineInit(context);
}
