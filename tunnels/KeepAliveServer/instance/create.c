#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *keepaliveserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(keepaliveserver_tstate_t), sizeof(keepaliveserver_lstate_t));
    if (! t)
    {
        return NULL;
    }

    t->fnInitU    = &keepaliveserverTunnelUpStreamInit;
    t->fnFinU     = &keepaliveserverTunnelUpStreamFinish;
    t->fnPayloadU = &keepaliveserverTunnelUpStreamPayload;

    t->fnInitD    = &keepaliveserverTunnelDownStreamInit;
    t->fnFinD     = &keepaliveserverTunnelDownStreamFinish;
    t->fnPayloadD = &keepaliveserverTunnelDownStreamPayload;

    return t;
}
