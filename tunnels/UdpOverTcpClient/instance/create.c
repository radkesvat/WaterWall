#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *udpovertcpclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(udpovertcpclient_tstate_t), sizeof(udpovertcpclient_lstate_t));

    t->fnInitU    = &udpovertcpclientTunnelUpStreamInit;
    t->fnEstU     = &udpovertcpclientTunnelUpStreamEst;
    t->fnFinU     = &udpovertcpclientTunnelUpStreamFinish;
    t->fnPayloadU = &udpovertcpclientTunnelUpStreamPayload;
    t->fnPauseU   = &udpovertcpclientTunnelUpStreamPause;
    t->fnResumeU  = &udpovertcpclientTunnelUpStreamResume;

    t->fnInitD    = &udpovertcpclientTunnelDownStreamInit;
    t->fnEstD     = &udpovertcpclientTunnelDownStreamEst;
    t->fnFinD     = &udpovertcpclientTunnelDownStreamFinish;
    t->fnPayloadD = &udpovertcpclientTunnelDownStreamPayload;
    t->fnPauseD   = &udpovertcpclientTunnelDownStreamPause;
    t->fnResumeD  = &udpovertcpclientTunnelDownStreamResume;

    t->onPrepare = &udpovertcpclientTunnelOnPrepair;
    t->onStart   = &udpovertcpclientTunnelOnStart;
    t->onDestroy = &udpovertcpclientTunnelDestroy;
    
    return t;
}
