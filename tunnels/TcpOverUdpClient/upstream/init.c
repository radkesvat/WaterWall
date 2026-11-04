#include "structure.h"

void tcpoverudpclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    if (! tcpoverudpclientSessionCreate(t, l))
        tunnelPrevDownStreamFinish(t, l);
}
