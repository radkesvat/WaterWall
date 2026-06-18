#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *routerTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(router_tstate_t), sizeof(router_lstate_t));

    t->fnInitU    = &routerTunnelUpStreamInit;
    t->fnEstU     = &routerTunnelUpStreamEst;
    t->fnFinU     = &routerTunnelUpStreamFinish;
    t->fnPayloadU = &routerTunnelUpStreamPayload;
    t->fnPauseU   = &routerTunnelUpStreamPause;
    t->fnResumeU  = &routerTunnelUpStreamResume;

    t->fnInitD    = &routerTunnelDownStreamInit;
    t->fnEstD     = &routerTunnelDownStreamEst;
    t->fnFinD     = &routerTunnelDownStreamFinish;
    t->fnPayloadD = &routerTunnelDownStreamPayload;
    t->fnPauseD   = &routerTunnelDownStreamPause;
    t->fnResumeD  = &routerTunnelDownStreamResume;

    t->onChain   = &routerTunnelOnChain;
    t->onIndex   = &routerTunnelOnIndex;
    t->onPrepare = &routerTunnelOnPrepair;
    t->onStart   = &routerTunnelOnStart;
    t->onStop    = &routerTunnelOnStop;
    t->onDestroy = &routerTunnelDestroy;

    if (! nodeHasNext(node))
    {
        LOGF("Router: must have a \"next\" fallback node (the default route)");
        routerTunnelDestroy(t);
        return NULL;
    }

    const cJSON *settings = node->node_settings_json;
    if (settings != NULL && ! cJSON_IsObject(settings))
    {
        LOGF("JSON Error: Router->settings (object field) : expected an object");
        routerTunnelDestroy(t);
        return NULL;
    }

    router_tstate_t *ts = tunnelGetState(t);
    if (settings != NULL && ! routerLoadRules(ts, node, settings))
    {
        routerTunnelDestroy(t);
        return NULL;
    }

    if (ts->rules_count == 0)
    {
        LOGW("Router: no routing rules configured; all connections use the default \"next\" route");
    }

    return t;
}
