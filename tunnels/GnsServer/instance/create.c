#include "GnsServer/structure.h"

tunnel_t *gnsserverTunnelCreate(node_t *node)
{
    tunnel_t *t = gnsEndpointCreate(node, kGnsServerEndpoint, &gnsserverOutput);
    if (! t)
    {
        return NULL;
    }

    t->fnInitU    = gnsserverTunnelUpStreamInit;
    t->fnEstU     = gnsserverTunnelUpStreamEst;
    t->fnPayloadU = gnsserverTunnelUpStreamPayload;
    t->fnPauseU   = gnsserverTunnelUpStreamPause;
    t->fnResumeU  = gnsserverTunnelUpStreamResume;
    t->fnFinU     = gnsserverTunnelUpStreamFinish;
    t->fnEstD     = gnsserverTunnelDownStreamEst;
    t->fnPayloadD = gnsserverTunnelDownStreamPayload;
    t->fnPauseD   = gnsserverTunnelDownStreamPause;
    t->fnResumeD  = gnsserverTunnelDownStreamResume;
    t->fnFinD     = gnsserverTunnelDownStreamFinish;
    return t;
}
