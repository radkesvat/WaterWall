#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *tcpoverudpserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(tcpoverudpserver_tstate_t), sizeof(tcpoverudpserver_lstate_t));

    t->fnInitU    = &tcpoverudpserverTunnelUpStreamInit;
    t->fnEstU     = &tcpoverudpserverTunnelUpStreamEst;
    t->fnFinU     = &tcpoverudpserverTunnelUpStreamFinish;
    t->fnPayloadU = &tcpoverudpserverTunnelUpStreamPayload;
    t->fnPauseU   = &tcpoverudpserverTunnelUpStreamPause;
    t->fnResumeU  = &tcpoverudpserverTunnelUpStreamResume;

    t->fnInitD    = &tcpoverudpserverTunnelDownStreamInit;
    t->fnEstD     = &tcpoverudpserverTunnelDownStreamEst;
    t->fnFinD     = &tcpoverudpserverTunnelDownStreamFinish;
    t->fnPayloadD = &tcpoverudpserverTunnelDownStreamPayload;
    t->fnPauseD   = &tcpoverudpserverTunnelDownStreamPause;
    t->fnResumeD  = &tcpoverudpserverTunnelDownStreamResume;

    t->onPrepair = &tcpoverudpserverTunnelOnPrepair;
    t->onStart   = &tcpoverudpserverTunnelOnStart;
    t->onDestroy = &tcpoverudpserverTunnelDestroy;

    tcpoverudpserver_tstate_t *ts = tunnelGetState(t);

    *ts = (tcpoverudpserver_tstate_t) {0};

    ikcp_allocator(&memoryAllocate, &memoryFree);

    return t;
}
