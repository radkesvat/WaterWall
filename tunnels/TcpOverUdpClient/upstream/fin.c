#include "structure.h"

void tcpoverudpclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);
    assert(ls->role == kTcpOverUdpClientApplication && ls->session != NULL);
    tcpoverudpclient_session_t *session = ls->session;
    tou_session_t              *driver  = session->driver;
    touSessionRetain(driver);
    tcpoverudpclientDetachApplication(session, false);
    tcpoverudpclient_tstate_t *ts = tunnelGetState(t);
    if (atomicLoadRelaxed(&ts->stopping) || ts->workers[session->wid].quiescing)
        touSessionAbort(driver, kTouAborted);
    else
        touSessionAppFinish(driver);
    touSessionRelease(driver);
}
