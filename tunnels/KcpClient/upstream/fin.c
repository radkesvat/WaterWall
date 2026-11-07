#include "structure.h"

void kcpclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    kcpclient_lstate_t *ls = lineGetState(l, t);
    assert(ls->role == kKcpClientApplication && ls->session != NULL);
    kcpclient_session_t *session = ls->session;
    tou_session_t       *driver  = session->driver;
    touSessionRetain(driver);
    kcpclientDetachApplication(session, false);
    kcpclient_tstate_t *ts = tunnelGetState(t);
    if (atomicLoadRelaxed(&ts->stopping) || ts->workers[session->wid].quiescing)
        touSessionAbort(driver, kTouAborted);
    else
        touSessionAppFinish(driver);
    touSessionRelease(driver);
}
