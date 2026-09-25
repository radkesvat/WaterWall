#include "structure.h"

void streamfragmenterTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    streamfragmenterLinestateDestroy(lineGetState(l, t));
    tunnelNextUpStreamFinish(t, l);
}
