#include "structure.h"

void httpproxyserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    hpsPressure(t, l, 1, true);
}
