#include "structure.h"

void quicclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    quic_finish_scope_t scope = quicBeginFinish(t, l, kQuicFinishFromPrev, kQuicFinishFlushApplication);
    if (scope.forward)
    {
        tunnelNextUpStreamFinish(t, l);
    }
    quicEndFinish(&scope);
}
