#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *httpserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(httpserver_tstate_t), sizeof(httpserver_lstate_t));

    t->fnInitU    = &httpserverTunnelUpStreamInit;
    t->fnEstU     = &httpserverTunnelUpStreamEst;
    t->fnFinU     = &httpserverTunnelUpStreamFinish;
    t->fnPayloadU = &httpserverTunnelUpStreamPayload;
    t->fnPauseU   = &httpserverTunnelUpStreamPause;
    t->fnResumeU  = &httpserverTunnelUpStreamResume;

    t->fnInitD    = &httpserverTunnelDownStreamInit;
    t->fnEstD     = &httpserverTunnelDownStreamEst;
    t->fnFinD     = &httpserverTunnelDownStreamFinish;
    t->fnPayloadD = &httpserverTunnelDownStreamPayload;
    t->fnPauseD   = &httpserverTunnelDownStreamPause;
    t->fnResumeD  = &httpserverTunnelDownStreamResume;

    t->onPrepare = &httpserverTunnelOnPrepair;
    t->onStart   = &httpserverTunnelOnStart;
    t->onDestroy = &httpserverTunnelDestroy;
    
    return t;
}
