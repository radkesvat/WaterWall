#include "structure.h"

void streamfragmenterTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    streamfragmenter_lstate_t *ls = lineGetState(l, t);
    ls->consumer_paused           = false;
    streamfragmenterDrain(t, l);
}
