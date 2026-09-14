#include "structure.h"

void httpproxyserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    hpsFinish(t, l, true);
}
