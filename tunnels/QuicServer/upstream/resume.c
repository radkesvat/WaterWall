#include "structure.h"

void quicserverTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    quicSetCarrierPaused(t, l, false);
}
