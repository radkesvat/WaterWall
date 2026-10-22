#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *headerclientTunnelCreate(node_t *node)
{
    headerclient_tstate_t settings = {0};
    if (! headerclientLoadSettings(&settings, node->node_settings_json))
    {
        return NULL;
    }

    bool protocol_mode = settings.data_mode == kHeaderClientDataModeSourceProtocol ||
                         settings.data_mode == kHeaderClientDataModeDestinationProtocol;
    tunnel_t *t = tunnelCreate(node, sizeof(headerclient_tstate_t), protocol_mode ? sizeof(headerclient_lstate_t) : 0);
    if (! t)
    {
        return NULL;
    }

    t->fnPayloadU = &headerclientTunnelUpStreamPayload;
    if (protocol_mode)
    {
        t->fnInitU = &headerclientTunnelUpStreamInit;
        t->fnFinU  = &headerclientTunnelUpStreamFinish;
        t->fnFinD  = &headerclientTunnelDownStreamFinish;
    }

    *(headerclient_tstate_t *) tunnelGetState(t) = settings;
    return t;
}
