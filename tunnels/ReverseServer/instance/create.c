#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *reverseserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(reverseserver_tstate_t), sizeof(reverseserver_lstate_t));

    t->fnInitU    = &reverseserverTunnelUpStreamInit;
    t->fnEstU     = &reverseserverTunnelUpStreamEst;
    t->fnFinU     = &reverseserverTunnelUpStreamFinish;
    t->fnPayloadU = &reverseserverTunnelUpStreamPayload;
    t->fnPauseU   = &reverseserverTunnelUpStreamPause;
    t->fnResumeU  = &reverseserverTunnelUpStreamResume;

    t->fnInitD    = &reverseserverTunnelDownStreamInit;
    t->fnEstD     = &reverseserverTunnelDownStreamEst;
    t->fnFinD     = &reverseserverTunnelDownStreamFinish;
    t->fnPayloadD = &reverseserverTunnelDownStreamPayload;
    t->fnPauseD   = &reverseserverTunnelDownStreamPause;
    t->fnResumeD  = &reverseserverTunnelDownStreamResume;

    t->onPrepair = &reverseserverTunnelOnPrepair;
    t->onStart   = &reverseserverTunnelOnStart;
    t->onDestroy = &reverseserverTunnelDestroy;

    tunnel_t *pipe_tunnel = pipetunnelCreate(t);
    return pipe_tunnel;
}
