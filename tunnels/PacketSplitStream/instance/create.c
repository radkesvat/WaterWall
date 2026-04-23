#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *packetsplitstreamTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(packetsplitstream_tstate_t), sizeof(packetsplitstream_lstate_t));

    t->fnInitU    = &packetsplitstreamTunnelUpStreamInit;
    t->fnEstU     = &packetsplitstreamTunnelUpStreamEst;
    t->fnFinU     = &packetsplitstreamTunnelUpStreamFinish;
    t->fnPayloadU = &packetsplitstreamTunnelUpStreamPayload;
    t->fnPauseU   = &packetsplitstreamTunnelUpStreamPause;
    t->fnResumeU  = &packetsplitstreamTunnelUpStreamResume;

    t->fnInitD    = &packetsplitstreamTunnelDownStreamInit;
    t->fnEstD     = &packetsplitstreamTunnelDownStreamEst;
    t->fnFinD     = &packetsplitstreamTunnelDownStreamFinish;
    t->fnPayloadD = &packetsplitstreamTunnelDownStreamPayload;
    t->fnPauseD   = &packetsplitstreamTunnelDownStreamPause;
    t->fnResumeD  = &packetsplitstreamTunnelDownStreamResume;

    t->onDestroy = &packetsplitstreamTunnelDestroy;
    t->onChain   = &packetsplitstreamTunnelOnChain;
    t->onPrepare = &packetsplitstreamTunnelOnPrepair;
    t->onStart   = &packetsplitstreamTunnelOnStart;

    if (nodeHasNext(node))
    {
        LOGF("PacketSplitStream: top-level \"next\" is not used, configure \"up\" and \"down\" in settings instead");
        tunnelDestroy(t);
        return NULL;
    }

    const cJSON *settings  = node->node_settings_json;
    char        *up_name   = NULL;
    char        *down_name = NULL;

    if (! getStringFromJsonObject(&up_name, settings, "up"))
    {
        LOGF("PacketSplitStream: missing required settings.up");
        tunnelDestroy(t);
        return NULL;
    }

    if (! getStringFromJsonObject(&down_name, settings, "down"))
    {
        LOGF("PacketSplitStream: missing required settings.down");
        memoryFree(up_name);
        tunnelDestroy(t);
        return NULL;
    }

    node_t *up_node   = nodemanagerGetConfigNodeByName(node->node_manager_config, up_name);
    node_t *down_node = nodemanagerGetConfigNodeByName(node->node_manager_config, down_name);

    if (up_node == NULL)
    {
        LOGF("PacketSplitStream: up node \"%s\" not found", up_name);
        memoryFree(up_name);
        memoryFree(down_name);
        tunnelDestroy(t);
        return NULL;
    }

    if (down_node == NULL)
    {
        LOGF("PacketSplitStream: down node \"%s\" not found", down_name);
        memoryFree(up_name);
        memoryFree(down_name);
        tunnelDestroy(t);
        return NULL;
    }

    if (up_node == down_node)
    {
        LOGF("PacketSplitStream: settings.up and settings.down must point to different nodes");
        memoryFree(up_name);
        memoryFree(down_name);
        tunnelDestroy(t);
        return NULL;
    }

    if (up_node == node || down_node == node)
    {
        LOGF("PacketSplitStream: up/down nodes must not point back to PacketSplitStream itself");
        memoryFree(up_name);
        memoryFree(down_name);
        tunnelDestroy(t);
        return NULL;
    }

    packetsplitstream_tstate_t *state = tunnelGetState(t);
    state->up_node                    = up_node;
    state->down_node                  = down_node;

    memoryFree(up_name);
    memoryFree(down_name);

    return t;
}
