#include "structure.h"

void streamfragmenterTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    streamfragmenterLinestateDestroy(lineGetState(l, t));
    tunnelPrevDownStreamFinish(t, l);
}
