#include "structure.h"

void socks5clientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    socks5clientSetNextPaused(t, l, false);
}
