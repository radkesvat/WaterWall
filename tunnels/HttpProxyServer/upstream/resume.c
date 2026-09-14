#include "structure.h"

void httpproxyserverTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    hpsPressure(t, l, 1, false);
}
