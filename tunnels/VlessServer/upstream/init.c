#include "structure.h"

void vlessserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    vlessserverLinestateInitialize(lineGetState(l, t), t, l, kVlessServerLineKindClient);
}
