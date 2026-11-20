#include "structure.h"

void quicclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    quicSetApplicationPaused(t, l, false);
}
