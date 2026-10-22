#include "structure.h"

void quicserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    quic_finish_scope_t scope = quicBeginFinish(t, l, kQuicFinishFromNext, kQuicFinishFlushApplication);
    if (scope.forward)
    {
        tunnelPrevDownStreamFinish(t, l);
    }
    quicEndFinish(&scope);
}
