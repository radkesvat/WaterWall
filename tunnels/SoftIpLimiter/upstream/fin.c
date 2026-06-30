#include "structure.h"

void softiplimiterTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    softiplimiterCloseLine(t, l, kSoftIpLimiterCloseFromPrev);
}

