#include "structure.h"

void reverseserverTunnelDownStreamResume(tunnel_t *t, line_t *u)
{
    reverseserverSetOutputPaused(t, u, false);
}
