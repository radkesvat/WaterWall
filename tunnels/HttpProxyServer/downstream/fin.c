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
        s->upload_stopped = true;
        hpsDiscardBuffer(s, &s->input[kHpsUpstream]);
        hpsDiscardBuffer(s, &s->output[kHpsUpstream]);
        hpsDiscardBuffer(s, &s->deferred[kHpsUpstream]);
        hpsDiscardBuffer(s, &s->incoming[kHpsUpstream]);
    }
    else if (s->phase == kHpsConnect)
        hpsFail(s, 502);
    hpsPump(s);
    hpsRelease(s);
}
