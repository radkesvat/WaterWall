#include "structure.h"

void quicclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    quic_finish_scope_t scope = quicBeginFinish(t, l, kQuicFinishFromNext, kQuicFinishDiscardCarrier);
    if (scope.forward)
    {
        tunnelPrevDownStreamFinish(t, l);
    }
    quicEndFinish(&scope);
}
