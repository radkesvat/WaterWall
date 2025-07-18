#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *bridgeTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(bridge_tstate_t), sizeof(bridge_lstate_t));

    t->fnInitU    = &bridgeTunnelUpStreamInit;
    t->fnEstU     = &bridgeTunnelUpStreamEst;
    t->fnFinU     = &bridgeTunnelUpStreamFinish;
    t->fnPayloadU = &bridgeTunnelUpStreamPayload;
    t->fnPauseU   = &bridgeTunnelUpStreamPause;
    t->fnResumeU  = &bridgeTunnelUpStreamResume;

    t->fnInitD    = &bridgeTunnelDownStreamInit;
    t->fnEstD     = &bridgeTunnelDownStreamEst;
    t->fnFinD     = &bridgeTunnelDownStreamFinish;
    t->fnPayloadD = &bridgeTunnelDownStreamPayload;
    t->fnPauseD   = &bridgeTunnelDownStreamPause;
    t->fnResumeD  = &bridgeTunnelDownStreamResume;

    t->onPrepair = &bridgeTunnelOnPrepair;
    t->onStart   = &bridgeTunnelOnStart;
    t->onDestroy = &bridgeTunnelDestroy;

    const cJSON *settings       = node->node_settings_json;
    char        *pair_node_name = NULL;
    if (! getStringFromJsonObject(&pair_node_name, settings, "pair"))
    {
        LOGF("Bridge: \"pair\" is not provided in json");
        tunnelDestroy(t);
        return NULL;
    }

    bridge_tstate_t *state = tunnelGetState(t);

    node_t *pair_node     = nodemanagerGetConfigNodeByName(node->node_manager_config, pair_node_name);
    if (pair_node == NULL)
    {
        LOGF("Bridge: pair node \"%s\" not found", pair_node_name);
        memoryFree(pair_node_name);
        tunnelDestroy(t);
        return NULL;
    }
    memoryFree(pair_node_name);

    state->pair_node   = pair_node;
    state->mode_upside = !nodeHasNext(node);

    return t;
}
