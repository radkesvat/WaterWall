#include "structure.h"

void quicserverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    quicSetApplicationPaused(t, l, false);
}
