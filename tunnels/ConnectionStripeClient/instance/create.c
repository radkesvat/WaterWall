#include "ConnectionStripeClient/structure.h"

tunnel_t *connectionstripeclientTunnelCreate(node_t *node)
{
    tunnel_t *t = connectionstripeCreate(node, kStripeClientEndpoint, &connectionstripeclientOutput);
    if (! t)
        return NULL;

    t->fnInitU    = connectionstripeclientTunnelUpStreamInit;
    t->fnPayloadU = connectionstripeclientTunnelUpStreamPayload;
    t->fnPayloadD = connectionstripeclientTunnelDownStreamPayload;
    t->fnFinU     = connectionstripeclientTunnelUpStreamFinish;
    t->fnFinD     = connectionstripeclientTunnelDownStreamFinish;
    t->fnEstU     = connectionstripeclientTunnelUpStreamEst;
    t->fnEstD     = connectionstripeclientTunnelDownStreamEst;
    t->fnPauseU   = connectionstripeclientTunnelUpStreamPause;
    t->fnPauseD   = connectionstripeclientTunnelDownStreamPause;
    t->fnResumeU  = connectionstripeclientTunnelUpStreamResume;
    t->fnResumeD  = connectionstripeclientTunnelDownStreamResume;
    return t;
}
