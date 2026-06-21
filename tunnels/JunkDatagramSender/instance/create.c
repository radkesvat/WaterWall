#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *junkdatagramsenderTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(junkdatagramsender_tstate_t), kLineStateSize);
    if (t == NULL)
    {
        return NULL;
    }

    t->fnInitU    = &junkdatagramsenderTunnelUpStreamInit;
    t->fnEstU     = &junkdatagramsenderTunnelUpStreamEst;
    t->fnFinU     = &junkdatagramsenderTunnelUpStreamFinish;
    t->fnPayloadU = &junkdatagramsenderTunnelUpStreamPayload;
    t->fnPauseU   = &junkdatagramsenderTunnelUpStreamPause;
    t->fnResumeU  = &junkdatagramsenderTunnelUpStreamResume;

    t->fnInitD    = &junkdatagramsenderTunnelDownStreamInit;
    t->fnEstD     = &junkdatagramsenderTunnelDownStreamEst;
    t->fnFinD     = &junkdatagramsenderTunnelDownStreamFinish;
    t->fnPayloadD = &junkdatagramsenderTunnelDownStreamPayload;
    t->fnPauseD   = &junkdatagramsenderTunnelDownStreamPause;
    t->fnResumeD  = &junkdatagramsenderTunnelDownStreamResume;

    t->onPrepare = &junkdatagramsenderTunnelOnPrepair;
    t->onStart   = &junkdatagramsenderTunnelOnStart;
    t->onStop    = &junkdatagramsenderTunnelOnStop;
    t->onDestroy = &junkdatagramsenderTunnelDestroy;

    junkdatagramsender_tstate_t *ts = tunnelGetState(t);
    if (! junkdatagramsenderLoadSettings(ts, node->node_settings_json))
    {
        tunnelDestroy(t);
        return NULL;
    }

    return t;
}
