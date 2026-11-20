#include "structure.h"

void reverseserverTunnelDownStreamPause(tunnel_t *t, line_t *u)
{
    reverseserverSetOutputPaused(t, u, true);
}
