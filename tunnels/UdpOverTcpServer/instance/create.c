#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *udpovertcpserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(udpovertcpserver_tstate_t), sizeof(udpovertcpserver_lstate_t));
    if (! t)
    {
        return NULL;
    }

    t->fnInitU    = &udpovertcpserverTunnelUpStreamInit;
    t->fnFinU     = &udpovertcpserverTunnelUpStreamFinish;
    t->fnPayloadU = &udpovertcpserverTunnelUpStreamPayload;
    t->fnPauseU   = &udpovertcpserverTunnelUpStreamPause;
    t->fnResumeU  = &udpovertcpserverTunnelUpStreamResume;
    t->fnFinD     = &udpovertcpserverTunnelDownStreamFinish;
    t->fnPayloadD = &udpovertcpserverTunnelDownStreamPayload;

    return t;
}
