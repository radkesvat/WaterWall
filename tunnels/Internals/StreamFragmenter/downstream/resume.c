#include "structure.h"

void streamfragmenterTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    streamfragmenter_lstate_t *ls = lineGetState(l, t);
    ls->next_paused               = false;
    if (! ls->source_paused)
        tunnelPrevDownStreamResume(t, l);
}
