#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *dataaspacketTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(dataaspacket_tstate_t), sizeof(dataaspacket_lstate_t));

    t->fnInitU    = &dataaspacketTunnelUpStreamInit;
    t->fnEstU     = &dataaspacketTunnelUpStreamEst;
    t->fnFinU     = &dataaspacketTunnelUpStreamFinish;
    t->fnPayloadU = &dataaspacketTunnelUpStreamPayload;
    t->fnPauseU   = &dataaspacketTunnelUpStreamPause;
    t->fnResumeU  = &dataaspacketTunnelUpStreamResume;

    t->fnInitD    = &dataaspacketTunnelDownStreamInit;
    t->fnEstD     = &dataaspacketTunnelDownStreamEst;
    t->fnFinD     = &dataaspacketTunnelDownStreamFinish;
    t->fnPayloadD = &dataaspacketTunnelDownStreamPayload;
    t->fnPauseD   = &dataaspacketTunnelDownStreamPause;
    t->fnResumeD  = &dataaspacketTunnelDownStreamResume;

    t->onPrepair = &dataaspacketTunnelOnPrepair;
    t->onStart   = &dataaspacketTunnelOnStart;
    t->onDestroy = &dataaspacketTunnelDestroy;
    
    return t;
}
