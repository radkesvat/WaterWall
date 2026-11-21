#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *headerclientTunnelCreate(node_t *node)
{
    headerclient_tstate_t settings = {0};
    if (! headerclientLoadSettings(&settings, node->node_settings_json))
    {
        return NULL;
    }

    const bool snapshot_header = settings.data_mode == kHeaderClientDataModeSourceProtocol ||
                                 settings.data_mode == kHeaderClientDataModeDestinationProtocol ||
                                 settings.data_mode == kHeaderClientDataModeLineMark;
    if (settings.data_mode == kHeaderClientDataModeDestinationProtocol)
        node->layer_group_prev_node = kNodeLayer4;
    tunnel_t *t =
        tunnelCreate(node, sizeof(headerclient_tstate_t), snapshot_header ? sizeof(headerclient_lstate_t) : 0);
    if (! t)
    {
        return NULL;
    }

    t->fnInitU    = &headerclientTunnelUpStreamInit;
    t->fnPayloadU = &headerclientTunnelUpStreamPayload;
    if (snapshot_header)
    {
        t->fnFinU = &headerclientTunnelUpStreamFinish;
        t->fnFinD = &headerclientTunnelDownStreamFinish;
    }

    *(headerclient_tstate_t *) tunnelGetState(t) = settings;
    return t;
}
