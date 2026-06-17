#include "structure.h"

void vlessserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    vlessserverCloseLineFromUpstream(t, l);
}
