#include "structure.h"

void quicclientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    quicSetCarrierPaused(t, l, true);
}
