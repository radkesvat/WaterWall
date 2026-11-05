#include "structure.h"

void quicclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    quicSetCarrierPaused(t, l, false);
}
