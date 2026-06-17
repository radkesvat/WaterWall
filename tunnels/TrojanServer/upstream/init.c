#include "structure.h"

void trojanserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    trojanserverLinestateInitialize(lineGetState(l, t), t, l, kTrojanServerLineKindClient);
}
