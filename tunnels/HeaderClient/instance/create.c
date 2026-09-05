#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *headerclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(headerclient_tstate_t), sizeof(headerclient_lstate_t));
    if (! t)
    {
        return NULL;
    }

    t->fnInitU    = &headerclientTunnelUpStreamInit;
    t->fnEstU     = &headerclientTunnelUpStreamEst;
    t->fnFinU     = &headerclientTunnelUpStreamFinish;
    t->fnPayloadU = &headerclientTunnelUpStreamPayload;

    t->fnInitD = &headerclientTunnelDownStreamInit;
    t->fnFinD  = &headerclientTunnelDownStreamFinish;

    headerclient_tstate_t *ts = tunnelGetState(t);
    if (! headerclientLoadSettings(ts, node->node_settings_json))
    {
        tunnelDestroy(t);
        return NULL;
    }

    return t;
}
