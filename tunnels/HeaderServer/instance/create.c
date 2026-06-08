#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *headerserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(headerserver_tstate_t), sizeof(headerserver_lstate_t));
    if (t == NULL)
    {
        return NULL;
    }

    t->fnInitU    = &headerserverTunnelUpStreamInit;
    t->fnEstU     = &headerserverTunnelUpStreamEst;
    t->fnFinU     = &headerserverTunnelUpStreamFinish;
    t->fnPayloadU = &headerserverTunnelUpStreamPayload;
    t->fnPauseU   = &headerserverTunnelUpStreamPause;
    t->fnResumeU  = &headerserverTunnelUpStreamResume;

    t->fnInitD    = &headerserverTunnelDownStreamInit;
    t->fnEstD     = &headerserverTunnelDownStreamEst;
    t->fnFinD     = &headerserverTunnelDownStreamFinish;
    t->fnPayloadD = &headerserverTunnelDownStreamPayload;
    t->fnPauseD   = &headerserverTunnelDownStreamPause;
    t->fnResumeD  = &headerserverTunnelDownStreamResume;

    t->onPrepare = &headerserverTunnelOnPrepair;
    t->onStart   = &headerserverTunnelOnStart;
    t->onStop    = &headerserverTunnelOnStop;
    t->onDestroy = &headerserverTunnelDestroy;

    headerserver_tstate_t *ts = tunnelGetState(t);
    if (! headerserverLoadSettings(ts, node->node_settings_json))
    {
        tunnelDestroy(t);
        return NULL;
    }

    return t;
}
