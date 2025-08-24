#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *udpovertcpserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(udpovertcpserver_tstate_t), sizeof(udpovertcpserver_lstate_t));

    t->fnInitU    = &udpovertcpserverTunnelUpStreamInit;
    t->fnEstU     = &udpovertcpserverTunnelUpStreamEst;
    t->fnFinU     = &udpovertcpserverTunnelUpStreamFinish;
    t->fnPayloadU = &udpovertcpserverTunnelUpStreamPayload;
    t->fnPauseU   = &udpovertcpserverTunnelUpStreamPause;
    t->fnResumeU  = &udpovertcpserverTunnelUpStreamResume;

    t->fnInitD    = &udpovertcpserverTunnelDownStreamInit;
    t->fnEstD     = &udpovertcpserverTunnelDownStreamEst;
    t->fnFinD     = &udpovertcpserverTunnelDownStreamFinish;
    t->fnPayloadD = &udpovertcpserverTunnelDownStreamPayload;
    t->fnPauseD   = &udpovertcpserverTunnelDownStreamPause;
    t->fnResumeD  = &udpovertcpserverTunnelDownStreamResume;

    t->onPrepare = &udpovertcpserverTunnelOnPrepair;
    t->onStart   = &udpovertcpserverTunnelOnStart;
    t->onDestroy = &udpovertcpserverTunnelDestroy;
    
    return t;
}
