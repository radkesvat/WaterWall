#include "internal.h"
void httpproxyclientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    hpcSetNextPaused(t, l, true);
}
