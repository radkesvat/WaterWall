#include "structure.h"

void reverseserverTunnelUpStreamPause(tunnel_t *t, line_t *d)
{
    reverseserverSetOutputPaused(t, d, true);
}
