#include "structure.h"

void tcpudplistenerTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamFinish(t, l);
}
