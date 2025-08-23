#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *httpclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(httpclient_tstate_t), sizeof(httpclient_lstate_t));

    t->fnInitU    = &httpclientTunnelUpStreamInit;
    t->fnEstU     = &httpclientTunnelUpStreamEst;
    t->fnFinU     = &httpclientTunnelUpStreamFinish;
    t->fnPayloadU = &httpclientTunnelUpStreamPayload;
    t->fnPauseU   = &httpclientTunnelUpStreamPause;
    t->fnResumeU  = &httpclientTunnelUpStreamResume;

    t->fnInitD    = &httpclientTunnelDownStreamInit;
    t->fnEstD     = &httpclientTunnelDownStreamEst;
    t->fnFinD     = &httpclientTunnelDownStreamFinish;
    t->fnPayloadD = &httpclientTunnelDownStreamPayload;
    t->fnPauseD   = &httpclientTunnelDownStreamPause;
    t->fnResumeD  = &httpclientTunnelDownStreamResume;

    t->onPrepair = &httpclientTunnelOnPrepair;
    t->onStart   = &httpclientTunnelOnStart;
    t->onDestroy = &httpclientTunnelDestroy;
    
    return t;
}
