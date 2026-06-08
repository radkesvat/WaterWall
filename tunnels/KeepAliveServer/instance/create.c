#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *keepaliveserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(keepaliveserver_tstate_t), sizeof(keepaliveserver_lstate_t));

    t->fnInitU    = &keepaliveserverTunnelUpStreamInit;
    t->fnEstU     = &keepaliveserverTunnelUpStreamEst;
    t->fnFinU     = &keepaliveserverTunnelUpStreamFinish;
    t->fnPayloadU = &keepaliveserverTunnelUpStreamPayload;
    t->fnPauseU   = &keepaliveserverTunnelUpStreamPause;
    t->fnResumeU  = &keepaliveserverTunnelUpStreamResume;

    t->fnInitD    = &keepaliveserverTunnelDownStreamInit;
    t->fnEstD     = &keepaliveserverTunnelDownStreamEst;
    t->fnFinD     = &keepaliveserverTunnelDownStreamFinish;
    t->fnPayloadD = &keepaliveserverTunnelDownStreamPayload;
    t->fnPauseD   = &keepaliveserverTunnelDownStreamPause;
    t->fnResumeD  = &keepaliveserverTunnelDownStreamResume;

    t->onPrepare = &keepaliveserverTunnelOnPrepair;
    t->onStart   = &keepaliveserverTunnelOnStart;
    t->onStop    = &keepaliveserverTunnelOnStop;
    t->onDestroy = &keepaliveserverTunnelDestroy;

    return t;
}
