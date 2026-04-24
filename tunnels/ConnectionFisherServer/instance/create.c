#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *connectionfisherserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(connectionfisherserver_tstate_t), sizeof(connectionfisherserver_lstate_t));

    t->fnInitU    = &connectionfisherserverTunnelUpStreamInit;
    t->fnEstU     = &connectionfisherserverTunnelUpStreamEst;
    t->fnFinU     = &connectionfisherserverTunnelUpStreamFinish;
    t->fnPayloadU = &connectionfisherserverTunnelUpStreamPayload;
    t->fnPauseU   = &connectionfisherserverTunnelUpStreamPause;
    t->fnResumeU  = &connectionfisherserverTunnelUpStreamResume;

    t->fnInitD    = &connectionfisherserverTunnelDownStreamInit;
    t->fnEstD     = &connectionfisherserverTunnelDownStreamEst;
    t->fnFinD     = &connectionfisherserverTunnelDownStreamFinish;
    t->fnPayloadD = &connectionfisherserverTunnelDownStreamPayload;
    t->fnPauseD   = &connectionfisherserverTunnelDownStreamPause;
    t->fnResumeD  = &connectionfisherserverTunnelDownStreamResume;

    t->onDestroy = &connectionfisherserverTunnelDestroy;

    return t;
}
