#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *bgp4serverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(bgp4server_tstate_t), sizeof(bgp4server_lstate_t));
    if (t == NULL)
    {
        return NULL;
    }

    t->fnInitU    = &bgp4serverTunnelUpStreamInit;
    t->fnEstU     = &bgp4serverTunnelUpStreamEst;
    t->fnFinU     = &bgp4serverTunnelUpStreamFinish;
    t->fnPayloadU = &bgp4serverTunnelUpStreamPayload;
    t->fnPauseU   = &bgp4serverTunnelUpStreamPause;
    t->fnResumeU  = &bgp4serverTunnelUpStreamResume;

    t->fnInitD    = &bgp4serverTunnelDownStreamInit;
    t->fnEstD     = &bgp4serverTunnelDownStreamEst;
    t->fnFinD     = &bgp4serverTunnelDownStreamFinish;
    t->fnPayloadD = &bgp4serverTunnelDownStreamPayload;
    t->fnPauseD   = &bgp4serverTunnelDownStreamPause;
    t->fnResumeD  = &bgp4serverTunnelDownStreamResume;

    t->onPrepare = &bgp4serverTunnelOnPrepair;
    t->onStart   = &bgp4serverTunnelOnStart;
    t->onDestroy = &bgp4serverTunnelDestroy;

    bgp4server_tstate_t *ts = tunnelGetState(t);
    if (! bgp4serverLoadSettings(ts, node->node_settings_json))
    {
        tunnelDestroy(t);
        return NULL;
    }

    return t;
}
