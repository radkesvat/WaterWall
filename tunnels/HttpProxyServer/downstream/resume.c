#include "structure.h"

void httpproxyserverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    hpsPressure(t, l, 0, false);
}
