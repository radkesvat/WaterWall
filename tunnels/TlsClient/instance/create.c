#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *tlsclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(tlsclient_tstate_t), sizeof(tlsclient_lstate_t));

    t->fnInitU    = &tlsclientTunnelUpStreamInit;
    t->fnEstU     = &tlsclientTunnelUpStreamEst;
    t->fnFinU     = &tlsclientTunnelUpStreamFinish;
    t->fnPayloadU = &tlsclientTunnelUpStreamPayload;
    t->fnPauseU   = &tlsclientTunnelUpStreamPause;
    t->fnResumeU  = &tlsclientTunnelUpStreamResume;

    t->fnInitD    = &tlsclientTunnelDownStreamInit;
    t->fnEstD     = &tlsclientTunnelDownStreamEst;
    t->fnFinD     = &tlsclientTunnelDownStreamFinish;
    t->fnPayloadD = &tlsclientTunnelDownStreamPayload;
    t->fnPauseD   = &tlsclientTunnelDownStreamPause;
    t->fnResumeD  = &tlsclientTunnelDownStreamResume;

    t->onPrepair = &tlsclientTunnelOnPrepair;
    t->onStart   = &tlsclientTunnelOnStart;
    t->onDestroy = &tlsclientTunnelDestroy;
    
    return t;
}
