#include "structure.h"

void streamfragmenterTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    streamfragmenter_lstate_t *ls = lineGetState(l, t);
    ls->consumer_paused           = true;
    discard streamfragmenterUpdatePressure(t, l);
}
