#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *halfduplexclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(halfduplexclient_tstate_t), sizeof(halfduplexclient_lstate_t));

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

    t->onPrepare = &halfduplexclientTunnelOnPrepair;
    t->onStart   = &halfduplexclientTunnelOnStart;
    t->onDestroy = &halfduplexclientTunnelDestroy;

    halfduplexclient_tstate_t* state = tunnelGetState(t);
    state->identifier = fastRand64() % 10000000;
    return t;
}
