#include "structure.h"

void socks5clientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    socks5clientSetNextPaused(t, l, true);
}
