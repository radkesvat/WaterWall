#include "structure.h"

#include "DomainResolver/interface.h"

#include "loggers/network_logger.h"

static char *routerMakeChildName(const node_t *node, const char *suffix)
{
    const char *base = node->name != NULL ? node->name : "Router";
    return stringConcat(base, suffix);
}

static bool routerConfigureDomainResolverNode(node_t *child, node_t template_node, const node_t *owner)
{
    *child = template_node;

    child->name = routerMakeChildName(owner, ".domain-resolver");
    if (child->name == NULL)
    {
        return false;
    }

    child->hash_name           = calcHashBytes(child->name, stringLength(child->name));
    child->next                = NULL;
    child->hash_next           = 0;
    child->version             = owner->version;
    child->flags               = kNodeFlagNone;
    child->node_json           = owner->node_json;
    child->node_settings_json  = NULL;
    child->node_manager_config = owner->node_manager_config;
    child->instance            = NULL;
    return true;
}

static bool routerLoadResolveDomains(router_tstate_t *ts, const cJSON *settings)
{
    ts->resolve_domains = false;

    if (settings == NULL)
    {
        return true;
    }

    const cJSON *resolve_domains = cJSON_GetObjectItemCaseSensitive(settings, "resolve-domains");
    if (resolve_domains == NULL)
    {
        return true;
    }

    if (! cJSON_IsBool(resolve_domains))
    {
        LOGF("JSON Error: Router->settings->resolve-domains (boolean field) : expected a boolean");
        return false;
    }

    ts->resolve_domains = cJSON_IsTrue(resolve_domains);
    return true;
}

static bool routerCreateInternalDomainResolver(tunnel_t *t, node_t *node)
{
    router_tstate_t *ts = tunnelGetState(t);

    if (! ts->resolve_domains)
    {
        return true;
    }

    if (! routerConfigureDomainResolverNode(&ts->domain_resolver_node, nodeDomainResolverGet(), node))
    {
        LOGF("Router: failed to configure internal DomainResolver node");
        return false;
    }

    ts->domain_resolver_tunnel = ts->domain_resolver_node.createHandle(&ts->domain_resolver_node);
    if (ts->domain_resolver_tunnel == NULL)
    {
        LOGF("Router: failed to create internal DomainResolver");
        return false;
    }

    domainresolverTunnelAllowMissingDestination(ts->domain_resolver_tunnel, true);
    ts->domain_resolver_node.instance = ts->domain_resolver_tunnel;
    return true;
}

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
    if (! routerLoadResolveDomains(ts, settings))
    {
        routerTunnelDestroy(t);
        return NULL;
    }

    if (! routerCreateInternalDomainResolver(t, node))
    {
        routerTunnelDestroy(t);
        return NULL;
    }

    if (! routerLoadSniffing(ts, settings))
    {
        routerTunnelDestroy(t);
        return NULL;
    }

    if (settings != NULL && ! routerLoadRules(ts, node, settings))
    {
        routerTunnelDestroy(t);
        return NULL;
    }

    if (ts->needs_http_upgrade_attribute && (ts->sniffing_modes & kRouterSniffHttp1) == 0)
    {
        LOGW("Router: attribute \"http_upgrade_present\" requires root sniffing mode \"http1\" to match");
    }

    if (! routerGeositeOpenIfNeeded(ts, settings))
    {
        routerTunnelDestroy(t);
        return NULL;
    }

    if (! routerGeoipOpenIfNeeded(ts, settings))
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
