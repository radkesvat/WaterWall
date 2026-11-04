#include "structure.h"

void tcpoverudpserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);
    assert(ls->kind == kTcpOverUdpServerService && ls->session != NULL);
    tcpoverudpserver_session_t *session = ls->session;
    tou_session_t              *engine  = session->engine;
    touSessionRetain(engine);
    /* We created this exact normal service line. It must be logically dead before this handler returns. */
    tcpoverudpserverRetireService(session, false);
    tcpoverudpserver_tstate_t *ts = tunnelGetState(t);
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
