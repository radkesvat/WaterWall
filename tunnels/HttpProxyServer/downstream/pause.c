#include "structure.h"

void httpproxyserverTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    hpsPressure(t, l, 0, true);
}
