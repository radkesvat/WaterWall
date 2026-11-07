#include "structure.h"

void kcpserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    kcpserver_lstate_t *ls = lineGetState(l, t);
    assert(ls->kind == kKcpServerService && ls->session != NULL);
    kcpserver_session_t *session = ls->session;
    tou_session_t       *engine  = session->engine;
    touSessionRetain(engine);
    /* We created this exact normal service line. It must be logically dead before this handler returns. */
    kcpserverRetireService(session, false);
    kcpserver_tstate_t *ts = tunnelGetState(t);
    if (! session->carrier->active || atomicLoadRelaxed(&ts->stopping))
    {
        touSessionAbort(engine, kTouAborted);
    }
    else
    {
        touSessionAppFinish(engine);
    }
    touSessionRelease(engine);
}
