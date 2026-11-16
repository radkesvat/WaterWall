#include "EnetServer/structure.h"

tunnel_t *enetserverTunnelCreate(node_t *node)
{
    tunnel_t *t = enetEndpointCreate(node, kEnetServerEndpoint, &enetserverOutput);
    if (! t)
    {
        return NULL;
    }

    t->fnInitU    = enetserverTunnelUpStreamInit;
    t->fnEstU     = enetserverTunnelUpStreamEst;
    t->fnPayloadU = enetserverTunnelUpStreamPayload;
    t->fnPauseU   = enetserverTunnelUpStreamPause;
    t->fnResumeU  = enetserverTunnelUpStreamResume;
    t->fnFinU     = enetserverTunnelUpStreamFinish;
    t->fnEstD     = enetserverTunnelDownStreamEst;
    t->fnPayloadD = enetserverTunnelDownStreamPayload;
    t->fnPauseD   = enetserverTunnelDownStreamPause;
    t->fnResumeD  = enetserverTunnelDownStreamResume;
    t->fnFinD     = enetserverTunnelDownStreamFinish;
    return t;
}
