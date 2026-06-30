#include "structure.h"

void softiplimiterTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    softiplimiterLinestateInitialize(lineGetState(l, t), l);
}

