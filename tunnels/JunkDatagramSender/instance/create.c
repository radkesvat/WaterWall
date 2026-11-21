#include "structure.h"

#include "loggers/network_logger.h"

static void junkdatagramsenderForwardUpStreamEst(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamEst(t, l);
}

tunnel_t *junkdatagramsenderTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(junkdatagramsender_tstate_t), kLineStateSize);
    if (! t)
    {
        return NULL;
    }

    t->fnInitU    = &junkdatagramsenderTunnelUpStreamInit;
    t->fnEstU     = &junkdatagramsenderForwardUpStreamEst;
    t->fnFinU     = &junkdatagramsenderTunnelUpStreamFinish;
    t->fnPayloadU = &junkdatagramsenderTunnelUpStreamPayload;

    t->fnInitD    = &junkdatagramsenderTunnelDownStreamInit;
    t->fnFinD     = &junkdatagramsenderTunnelDownStreamFinish;
    t->fnPayloadD = &junkdatagramsenderTunnelDownStreamPayload;

    t->onWorkerStop = &junkdatagramsenderTunnelOnWorkerStop;

    junkdatagramsender_tstate_t *ts = tunnelGetState(t);
    if (! junkdatagramsenderLoadSettings(ts, node->node_settings_json))
    {
        tunnelDestroy(t);
        return NULL;
    }

    if (junkdatagramsenderGenerationEnabled(ts))
    {
        node->layer_group_prev_node = kNodeLayer3 | kNodeLayer4Datagram | kNodeLayerSameAsNext;
        node->layer_group_next_node = kNodeLayer3 | kNodeLayer4Datagram | kNodeLayerSameAsPrev;
    }
    return t;
}
