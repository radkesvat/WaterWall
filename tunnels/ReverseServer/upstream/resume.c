#include "structure.h"

void reverseserverTunnelUpStreamResume(tunnel_t *t, line_t *d)
{
    reverseserverSetOutputPaused(t, d, false);
}
