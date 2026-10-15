#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *bgp4clientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(bgp4client_tstate_t), sizeof(bgp4client_lstate_t));
    if (! t)
    {
        return NULL;
    }

    t->fnInitU    = &bgp4clientTunnelUpStreamInit;
    t->fnFinU     = &bgp4clientTunnelUpStreamFinish;
    t->fnPayloadU = &bgp4clientTunnelUpStreamPayload;
    t->fnFinD     = &bgp4clientTunnelDownStreamFinish;
    t->fnPayloadD = &bgp4clientTunnelDownStreamPayload;

    bgp4client_tstate_t *ts = tunnelGetState(t);
    ts->as_number           = (uint16_t) fastRand();
    ts->router_id           = fastRand() * 3U;

    return t;
}
