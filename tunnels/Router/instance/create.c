#include "structure.h"

#include "DomainResolver/interface.h"

#include "loggers/network_logger.h"

static bool routerLoadResolveDomains(router_tstate_t *ts, const cJSON *settings)
{
    const dns_policy_defaults_t defaults = {
        .resolve       = false,
        .strategy      = GSTATE.domain_strategy,
        .core_strategy = GSTATE.domain_strategy,
    };
    if (! dnsPolicyParseSettings(&ts->dns_policy, settings, &defaults, "Router->settings->dns-behaviour"))
        return false;
    ts->resolve_domains = ts->dns_policy.resolve;
    return true;
}

static bool routerCreateInternalDomainResolver(tunnel_t *t, node_t *node)
{
    router_tstate_t *ts = tunnelGetState(t);

    if (! ts->resolve_domains)
    {
        return true;
    }

    ts->domain_resolver_settings = dnsPolicyCreateResolverSettings(&ts->dns_policy);
    if (! nodeConfigureChild(&ts->domain_resolver_node,
                             nodeDomainResolverGet(),
                             node,
                             ".domain-resolver",
                             kNodeChildLinkNone,
                             ts->domain_resolver_settings))
    {
        LOGF("Router: failed to configure internal DomainResolver node");
        return false;
    }
    ts->domain_resolver_tunnel = nodemanagerCreateTunnelInstance(&ts->domain_resolver_node);
    if (ts->domain_resolver_tunnel == NULL)
    {
        LOGF("Router: failed to create internal DomainResolver");
        return false;
    }

    domainresolverTunnelAllowMissingDestination(ts->domain_resolver_tunnel, true);
    ts->domain_resolver_node.instance = ts->domain_resolver_tunnel;
    return true;
}

static void routerWarnSharedDnsSniffing(const router_tstate_t *ts)
{
    if (! ts->resolve_domains || ts->dns_policy.mode != kDnsPolicyModeChain || ts->dns_policy.dns_next != NULL)
        return;

    if (ts->sniffing_modes != 0)
    {
        LOGW("Router: shared DNS TCP fallback waits for transport establishment before sending payload, but root "
             "sniffing delays route selection; remove root sniffing or configure a separate dns-next branch");
        return;
    }

    for (uint32_t i = 0; i < ts->rules_count; ++i)
    {
        const router_rule_t *rule = &ts->rules[i];
        if (rule->protocol.present || rule->attributes.present)
        {
            LOGW("Router: shared DNS TCP fallback may stall at payload-dependent rule %u before route selection; "
                 "place an unconditional resolver-dns rule first or configure a separate dns-next branch",
                 (unsigned) (i + 1));
            return;
        }

        /* A metadata-only rule that certainly accepts generated TCP DNS makes
         * later payload rules harmless. More selective rules may not match all
         * configured DNS servers, so they cannot establish that guarantee. */
        if ((! rule->resolver_dns.present || rule->resolver_dns.wanted) &&
            (! rule->network.present || (rule->network.wanted & kRouterNetworkTcp) != 0) &&
            ! rule->source_ips.present && ! rule->source_port.present && ! rule->destination_ip.present &&
            ! rule->destination_domain.present && ! rule->destination_port.present && ! rule->username.present &&
            ! rule->password.present)
            return;
    }
}

tunnel_t *routerTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(router_tstate_t), sizeof(router_lstate_t));
    if (! t)
    {
        return NULL;
    }

    t->fnInitU    = &routerTunnelUpStreamInit;
    t->fnFinU     = &routerTunnelUpStreamFinish;
    t->fnPayloadU = &routerTunnelUpStreamPayload;
    t->fnPauseU   = &routerTunnelUpStreamPause;
    t->fnResumeU  = &routerTunnelUpStreamResume;
    t->fnFinD = &routerTunnelDownStreamFinish;

    t->onChain   = &routerTunnelOnChain;

    t->onDestroy = &routerTunnelDestroy;

    if (! nodeHasNext(node))
    {
        LOGF("Router: must have a \"next\" fallback node (the default route)");
        routerTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    const cJSON *settings = node->node_settings_json;
    if (settings != NULL && ! cJSON_IsObject(settings))
    {
        LOGF("JSON Error: Router->settings (object field) : expected an object");
        routerTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    router_tstate_t *ts = tunnelGetState(t);
    if (! routerLoadResolveDomains(ts, settings))
    {
        routerTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    if (! routerCreateInternalDomainResolver(t, node))
    {
        routerTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    if (! routerLoadSniffing(ts, settings))
    {
        routerTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    if (settings != NULL && ! routerRuleTableLoad(ts, node, settings))
    {
        routerTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    if (ts->needs_http_upgrade_attribute && (ts->sniffing_modes & kRouterSniffHttp1) == 0)
    {
        LOGW("Router: attribute \"http_upgrade_present\" requires root sniffing mode \"http1\" to match");
    }

    if (! routerGeositeOpenIfNeeded(ts, settings))
    {
        routerTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    if (! routerGeoipOpenIfNeeded(ts, settings))
    {
        routerTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    if (ts->rules_count == 0)
    {
        LOGW("Router: no routing rules configured; all connections use the default \"next\" route");
    }

    routerWarnSharedDnsSniffing(ts);
    return t;
}
