#include "EnetClient/structure.h"

tunnel_t *enetclientTunnelCreate(node_t *node)
{
    tunnel_t *t = enetEndpointCreate(node, kEnetClientEndpoint, &enetclientOutput);
    if (! t)
    {
        return NULL;
    }

    t->fnInitU    = enetclientTunnelUpStreamInit;
    t->fnEstU     = enetclientTunnelUpStreamEst;
    t->fnPayloadU = enetclientTunnelUpStreamPayload;
    t->fnPauseU   = enetclientTunnelUpStreamPause;
    t->fnResumeU  = enetclientTunnelUpStreamResume;
    t->fnFinU     = enetclientTunnelUpStreamFinish;
    t->fnEstD     = enetclientTunnelDownStreamEst;
    t->fnPayloadD = enetclientTunnelDownStreamPayload;
    t->fnPauseD   = enetclientTunnelDownStreamPause;
    t->fnResumeD  = enetclientTunnelDownStreamResume;
    t->fnFinD     = enetclientTunnelDownStreamFinish;
    return t;
}
