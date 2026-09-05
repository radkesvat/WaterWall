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
    t->fnEstU     = &bgp4clientTunnelUpStreamEst;
    t->fnFinU     = &bgp4clientTunnelUpStreamFinish;
    t->fnPayloadU = &bgp4clientTunnelUpStreamPayload;

    t->fnInitD    = &bgp4clientTunnelDownStreamInit;
    t->fnFinD     = &bgp4clientTunnelDownStreamFinish;
    t->fnPayloadD = &bgp4clientTunnelDownStreamPayload;

    bgp4client_tstate_t *ts = tunnelGetState(t);
    if (! bgp4clientLoadSettings(ts, node->node_settings_json))
    {
        tunnelDestroy(t);
        return NULL;
    }

    return t;
}
