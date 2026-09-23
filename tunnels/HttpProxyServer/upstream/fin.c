#include "structure.h"

void httpproxyserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    hps_lstate_t  *ls = lineGetState(l, t);
    hps_session_t *s  = ls->session;
    assert(s && ! ls->child);
    hpsRetain(s);
    hpsClose(s, true); /* Borrowed client: finish only its owned child. */
    hpsRelease(s);
}
