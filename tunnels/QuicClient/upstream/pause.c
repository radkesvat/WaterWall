#include "structure.h"

void quicclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    quicSetApplicationPaused(t, l, true);
}
