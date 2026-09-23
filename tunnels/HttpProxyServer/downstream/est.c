#include "structure.h"

void httpproxyserverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    hps_lstate_t  *ls = lineGetState(l, t);
    hps_session_t *s  = ls->session;
    hpsRetain(s);
    lineRef(l);
    s->child_established = true;
    s->connect_at        = 0;
    s->progress_at       = hpsNowMs(s);
    if (! s->established)
    {
        s->established = true;
        tunnelPrevDownStreamEst(t, s->client);
    }
    if (hpsIsActive(s))
        hpsPump(s);
    lineUnref(l);
    hpsRelease(s);
}
