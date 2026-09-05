#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *junkdatagramsenderTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(junkdatagramsender_tstate_t), kLineStateSize);
    if (! t)
    {
        return NULL;
    }

    t->fnInitU    = &junkdatagramsenderTunnelUpStreamInit;
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

    return t;
}
