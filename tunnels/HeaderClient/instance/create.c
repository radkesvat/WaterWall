#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *headerclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(headerclient_tstate_t), sizeof(headerclient_lstate_t));
    if (t == NULL)
    {
        return NULL;
    }

    t->fnInitU    = &headerclientTunnelUpStreamInit;
    t->fnEstU     = &headerclientTunnelUpStreamEst;
    t->fnFinU     = &headerclientTunnelUpStreamFinish;
    t->fnPayloadU = &headerclientTunnelUpStreamPayload;
    t->fnPauseU   = &headerclientTunnelUpStreamPause;
    t->fnResumeU  = &headerclientTunnelUpStreamResume;

    t->fnInitD    = &headerclientTunnelDownStreamInit;
    t->fnEstD     = &headerclientTunnelDownStreamEst;
    t->fnFinD     = &headerclientTunnelDownStreamFinish;
    t->fnPayloadD = &headerclientTunnelDownStreamPayload;
    t->fnPauseD   = &headerclientTunnelDownStreamPause;
    t->fnResumeD  = &headerclientTunnelDownStreamResume;

    t->onPrepare = &headerclientTunnelOnPrepair;
    t->onStart   = &headerclientTunnelOnStart;
    t->onStop    = &headerclientTunnelOnStop;
    t->onDestroy = &headerclientTunnelDestroy;

    headerclient_tstate_t *ts = tunnelGetState(t);
    if (! headerclientLoadSettings(ts, node->node_settings_json))
    {
        tunnelDestroy(t);
        return NULL;
    }

    return t;
}
