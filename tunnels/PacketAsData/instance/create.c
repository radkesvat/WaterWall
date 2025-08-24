#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *packetasdataTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(packetasdata_tstate_t), sizeof(packetasdata_lstate_t));

    t->fnInitU    = &packetasdataTunnelUpStreamInit;
    t->fnEstU     = &packetasdataTunnelUpStreamEst;
    t->fnFinU     = &packetasdataTunnelUpStreamFinish;
    t->fnPayloadU = &packetasdataTunnelUpStreamPayload;
    t->fnPauseU   = &packetasdataTunnelUpStreamPause;
    t->fnResumeU  = &packetasdataTunnelUpStreamResume;

    t->fnInitD    = &packetasdataTunnelDownStreamInit;
    t->fnEstD     = &packetasdataTunnelDownStreamEst;
    t->fnFinD     = &packetasdataTunnelDownStreamFinish;
    t->fnPayloadD = &packetasdataTunnelDownStreamPayload;
    t->fnPauseD   = &packetasdataTunnelDownStreamPause;
    t->fnResumeD  = &packetasdataTunnelDownStreamResume;

    t->onPrepare = &packetasdataTunnelOnPrepair;
    t->onStart   = &packetasdataTunnelOnStart;
    t->onDestroy = &packetasdataTunnelDestroy;
    
    return t;
}
