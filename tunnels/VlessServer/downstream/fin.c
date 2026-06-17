#include "structure.h"

void vlessserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    vlessserverCloseLineFromDownstream(t, l);
}
