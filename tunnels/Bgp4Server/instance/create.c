#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *bgp4serverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(bgp4server_tstate_t), sizeof(bgp4server_lstate_t));
    if (! t)
    {
        return NULL;
    }

    t->fnInitU    = &bgp4serverTunnelUpStreamInit;
    t->fnFinU     = &bgp4serverTunnelUpStreamFinish;
    t->fnPayloadU = &bgp4serverTunnelUpStreamPayload;
    t->fnFinD     = &bgp4serverTunnelDownStreamFinish;
    t->fnPayloadD = &bgp4serverTunnelDownStreamPayload;

    bgp4server_tstate_t *ts = tunnelGetState(t);
    ts->as_number           = (uint16_t) fastRand();
    ts->router_id           = fastRand() * 3U;

    return t;
}
