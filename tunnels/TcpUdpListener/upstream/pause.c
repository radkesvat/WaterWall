#include "structure.h"

void tcpudplistenerTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamPause(t, l);
}
