#include "structure.h"

void httpproxyserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    hps_lstate_t  *ls = lineGetState(l, t);
    hps_session_t *s  = ls->session;
    assert(s && ls->child);
    hpsRetain(s);
    hpsCloseChild(s, true); /* The owned child is logically dead before any client-side continuation. */
    s->child_eof = true;
    if (s->phase == kHpsFallback || s->phase == kHpsRelay)
    {
        hps_direction_state_t *up = &s->directions[kHpsUpstream];
        s->upload_stopped = true;
        hpsDiscardBuffer(s, &up->input);
        hpsDiscardBuffer(s, &up->output);
        hpsDiscardBuffer(s, &up->deferred);
        hpsDiscardBuffer(s, &up->incoming);
    }
    else if (s->phase == kHpsConnect)
        hpsFail(s, 502);
    hpsPump(s);
    hpsRelease(s);
}
