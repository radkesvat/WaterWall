#include "structure.h"

void tcpudplistenerTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tunnelNextUpStreamPayload(t, l, buf);
}
