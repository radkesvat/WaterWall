#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *udpovertcpclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(udpovertcpclient_tstate_t), sizeof(udpovertcpclient_lstate_t));
    if (! t)
    {
        return NULL;
    }

    t->fnInitU    = &udpovertcpclientTunnelUpStreamInit;
    t->fnEstU     = &udpovertcpclientTunnelUpStreamEst;
    t->fnFinU     = &udpovertcpclientTunnelUpStreamFinish;
    t->fnPayloadU = &udpovertcpclientTunnelUpStreamPayload;

    t->fnInitD    = &udpovertcpclientTunnelDownStreamInit;
    t->fnFinD     = &udpovertcpclientTunnelDownStreamFinish;
    t->fnPayloadD = &udpovertcpclientTunnelDownStreamPayload;

    return t;
}
