#include "structure.h"

void quicserverTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    quicSetApplicationPaused(t, l, true);
}
