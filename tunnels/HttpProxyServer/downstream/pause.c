#include "structure.h"

void httpproxyserverTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    hps_lstate_t  *ls = lineGetState(l, t);
    hps_session_t *s  = ls->session;
    hpsRetain(s);
    lineRef(l);
    s->paused[kHpsUpstream] = true;
    hpsUpdatePressure(s);
    hpsPump(s);
    lineUnref(l);
    hpsRelease(s);
}
