#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *headerserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(headerserver_tstate_t), sizeof(headerserver_lstate_t));
    if (! t)
    {
        return NULL;
    }

    t->fnInitU    = &headerserverTunnelUpStreamInit;
    t->fnFinU     = &headerserverTunnelUpStreamFinish;
    t->fnPayloadU = &headerserverTunnelUpStreamPayload;
    t->fnPauseU   = &headerserverTunnelUpStreamPause;
    t->fnResumeU  = &headerserverTunnelUpStreamResume;
    t->fnEstD     = &headerserverTunnelDownStreamEst;
    t->fnFinD     = &headerserverTunnelDownStreamFinish;
    t->fnPayloadD = &headerserverTunnelDownStreamPayload;
    t->fnPauseD   = &headerserverTunnelDownStreamPause;
    t->fnResumeD  = &headerserverTunnelDownStreamResume;

    headerserver_tstate_t *ts = tunnelGetState(t);
    if (! headerserverLoadSettings(ts, node->node_settings_json))
    {
        tunnelDestroy(t);
        return NULL;
    }

    if (ts->override_mode == kHeaderServerOverrideModeConstant)
    {
        node->layer_group_prev_node = kNodeLayer4;
        node->layer_group_next_node = kNodeLayer4;
    }
    else
    {
        node->layer_group_prev_node = kNodeLayer4Stream;
        node->layer_group_next_node =
            ts->override_mode == kHeaderServerOverrideModeHeaderProtocol ? kNodeLayer4 : kNodeLayer4Stream;
    }
    return t;
}
