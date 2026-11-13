#include "ConnectionStripeServer/structure.h"

tunnel_t *connectionstripeserverTunnelCreate(node_t *node)
{
    tunnel_t *t = connectionstripeCreate(node, kStripeServerEndpoint, &connectionstripeserverOutput);
    if (! t)
        return NULL;

    t->fnInitU    = connectionstripeserverTunnelUpStreamInit;
    t->fnPayloadU = connectionstripeserverTunnelUpStreamPayload;
    t->fnPayloadD = connectionstripeserverTunnelDownStreamPayload;
    t->fnFinU     = connectionstripeserverTunnelUpStreamFinish;
    t->fnFinD     = connectionstripeserverTunnelDownStreamFinish;
    t->fnEstU     = connectionstripeserverTunnelUpStreamEst;
    t->fnEstD     = connectionstripeserverTunnelDownStreamEst;
    t->fnPauseU   = connectionstripeserverTunnelUpStreamPause;
    t->fnPauseD   = connectionstripeserverTunnelDownStreamPause;
    t->fnResumeU  = connectionstripeserverTunnelUpStreamResume;
    t->fnResumeD  = connectionstripeserverTunnelDownStreamResume;

    tunnel_t *wrapper = pipetunnelCreate(t);
    if (! wrapper)
        t->onDestroy(t, wwLifecycleStartupRollback());
    return wrapper;
}
