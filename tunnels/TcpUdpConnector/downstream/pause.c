#include "structure.h"

void tcpudpconnectorTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    tunnelPrevDownStreamPause(t, l);
}
