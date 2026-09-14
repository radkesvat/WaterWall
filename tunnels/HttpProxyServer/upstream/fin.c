#include "structure.h"

void httpproxyserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    hpsFinish(t, l, false);
}
