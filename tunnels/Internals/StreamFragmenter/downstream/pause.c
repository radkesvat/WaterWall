#include "structure.h"

void streamfragmenterTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    streamfragmenter_lstate_t *ls = lineGetState(l, t);
    ls->next_paused               = true;
    if (! ls->source_paused)
        tunnelPrevDownStreamPause(t, l);
}
