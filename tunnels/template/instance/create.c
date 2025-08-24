#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *templateTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(template_tstate_t), sizeof(template_lstate_t));

    t->fnInitU    = &templateTunnelUpStreamInit;
    t->fnEstU     = &templateTunnelUpStreamEst;
    t->fnFinU     = &templateTunnelUpStreamFinish;
    t->fnPayloadU = &templateTunnelUpStreamPayload;
    t->fnPauseU   = &templateTunnelUpStreamPause;
    t->fnResumeU  = &templateTunnelUpStreamResume;

    t->fnInitD    = &templateTunnelDownStreamInit;
    t->fnEstD     = &templateTunnelDownStreamEst;
    t->fnFinD     = &templateTunnelDownStreamFinish;
    t->fnPayloadD = &templateTunnelDownStreamPayload;
    t->fnPauseD   = &templateTunnelDownStreamPause;
    t->fnResumeD  = &templateTunnelDownStreamResume;

    t->onPrepare = &templateTunnelOnPrepair;
    t->onStart   = &templateTunnelOnStart;
    t->onDestroy = &templateTunnelDestroy;
    
    return t;
}
