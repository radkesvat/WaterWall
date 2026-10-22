#include "structure.h"

void quicserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    quic_finish_scope_t scope = quicBeginFinish(t, l, kQuicFinishFromPrev, kQuicFinishDiscardCarrier);
    if (scope.forward)
    {
        tunnelNextUpStreamFinish(t, l);
    }
    quicEndFinish(&scope);
}
