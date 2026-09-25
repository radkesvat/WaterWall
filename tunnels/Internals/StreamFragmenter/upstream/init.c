#include "structure.h"

void streamfragmenterTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    streamfragmenterLinestateInitialize(lineGetState(l, t), t, l);
    tunnelNextUpStreamInit(t, l);
}
