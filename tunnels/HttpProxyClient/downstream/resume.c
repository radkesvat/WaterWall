#include "internal.h"
void httpproxyclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    hpcSetNextPaused(t, l, false);
}
