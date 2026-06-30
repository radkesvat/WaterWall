#include "structure.h"

void softiplimiterTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    softiplimiterCloseLine(t, l, kSoftIpLimiterCloseFromNext);
}

