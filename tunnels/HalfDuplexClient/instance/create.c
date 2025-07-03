#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *halfduplexclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, 0, sizeof(halfduplexclient_lstate_t));

    t->fnInitU    = &halfduplexclientTunnelUpStreamInit;
    t->fnEstU     = &halfduplexclientTunnelUpStreamEst;
    t->fnFinU     = &halfduplexclientTunnelUpStreamFinish;
    t->fnPayloadU = &halfduplexclientTunnelUpStreamPayload;
    t->fnPauseU   = &halfduplexclientTunnelUpStreamPause;
    t->fnResumeU  = &halfduplexclientTunnelUpStreamResume;

    t->fnInitD    = &halfduplexclientTunnelDownStreamInit;
    t->fnEstD     = &halfduplexclientTunnelDownStreamEst;
    t->fnFinD     = &halfduplexclientTunnelDownStreamFinish;
    t->fnPayloadD = &halfduplexclientTunnelDownStreamPayload;
    t->fnPauseD   = &halfduplexclientTunnelDownStreamPause;
    t->fnResumeD  = &halfduplexclientTunnelDownStreamResume;

    t->onPrepair = &halfduplexclientTunnelOnPrepair;
    t->onStart   = &halfduplexclientTunnelOnStart;
    t->onDestroy = &halfduplexclientTunnelDestroy;
    
    return t;
}
