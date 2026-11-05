#include "structure.h"

void quicserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    quicSetCarrierPaused(t, l, true);
}
