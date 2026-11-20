#include "GnsClient/structure.h"

tunnel_t *gnsclientTunnelCreate(node_t *node)
{
    tunnel_t *t = gnsEndpointCreate(node, kGnsClientEndpoint, &gnsclientOutput);
    if (! t)
    {
        return NULL;
    }

    t->fnInitU    = gnsclientTunnelUpStreamInit;
    t->fnEstU     = gnsclientTunnelUpStreamEst;
    t->fnPayloadU = gnsclientTunnelUpStreamPayload;
    t->fnPauseU   = gnsclientTunnelUpStreamPause;
    t->fnResumeU  = gnsclientTunnelUpStreamResume;
    t->fnFinU     = gnsclientTunnelUpStreamFinish;
    t->fnEstD     = gnsclientTunnelDownStreamEst;
    t->fnPayloadD = gnsclientTunnelDownStreamPayload;
    t->fnPauseD   = gnsclientTunnelDownStreamPause;
    t->fnResumeD  = gnsclientTunnelDownStreamResume;
    t->fnFinD     = gnsclientTunnelDownStreamFinish;
    return t;
}
