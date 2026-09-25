#include "structure.h"

void streamfragmenterTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    streamfragmenter_lstate_t *ls = lineGetState(l, t);
    if (! ls->waiting_for_est || ls->est_received)
    {
        tunnelPrevDownStreamEst(t, l);
        return;
    }

    const streamfragmenter_tstate_t *ts = tunnelGetState(t);
    ls->est_received                    = true;
    if (ts->timed)
        ls->deadline_us = getHRTimeUs() + (uint64_t) ts->scope * 1000;

    /* Keep the startup gate closed across Est: nested input, Resume and Est
     * cannot start output or timers before the outer notification returns. */
    if (! lineCallWithRef(l, tunnelPrevDownStreamEst, t) || ls->tunnel != t)
        return;
    ls->waiting_for_est = false;
    streamfragmenterDrain(t, l);
}
