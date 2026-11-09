#include "structure.h"

#include "DomainResolver/interface.h"

#include "loggers/network_logger.h"

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

static bool routerCreateInternalDomainResolver(tunnel_t *t, node_t *node, const cJSON *settings)
{
    router_tstate_t *ts = tunnelGetState(t);

    /* An absent "dns" object keeps the internal resolver on the worker c-ares
     * channel (mode "core"), exactly as before. */
    const cJSON           *dns      = settings != NULL ? cJSON_GetObjectItemCaseSensitive(settings, "dns") : NULL;
    dnslineclient_mode_e   dns_mode = kDnsLineClientModeCore;
    dnslineclient_config_t dns_cfg  = {0};
    if (dns != NULL && ! cJSON_IsObject(dns))
    {
        LOGF("JSON Error: Router->settings->dns (object field) : expected an object");
        return false;
    }
    if (dns != NULL)
    {
        /* Nothing else may live in this object: a typo here would silently
         * turn chain DNS off and leak queries through core c-ares. */
        const cJSON *dns_key = NULL;
        cJSON_ArrayForEach(dns_key, dns)
        {
            if (! dnslineclientConfigIsKnownKey(dns_key->string))
            {
                LOGF("JSON Error: Router->settings->dns->%s : unknown key", dns_key->string != NULL ? dns_key->string : "");
                return false;
            }
        }
    }
    if (! dnslineclientConfigParse(dns, "Router->settings->dns", &dns_mode, &dns_cfg))
    {
        return false;
    }

    ts->dns_chain_mode = dns_mode == kDnsLineClientModeChain;
    if (ts->dns_chain_mode && ! ts->resolve_domains)
    {
        LOGF("JSON Error: Router->settings->dns->mode : \"chain\" requires Router->settings->resolve-domains to be "
             "true");
        return false;
    }

    if (! ts->resolve_domains)
    {
        return true;
    }

    if (! nodeConfigureChild(
            &ts->domain_resolver_node, nodeDomainResolverGet(), node, ".domain-resolver", kNodeChildLinkNone, NULL))
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
    if (ts->dns_chain_mode)
    {
        domainresolverTunnelSetChainResolver(ts->domain_resolver_tunnel, &dns_cfg, t, routerInjectResolverLine);
        _Static_assert(sizeof(((router_tstate_t *) 0)->dns_chain_server_ips) / sizeof(ip_addr_t) == kDnsLineClientMaxServers,
                       "dns server copy size");
        ts->dns_chain_servers_count = (uint8_t) dns_cfg.servers_count;
        for (uint32_t i = 0; i < dns_cfg.servers_count; ++i)
        {
            ts->dns_chain_server_ips[i]   = dns_cfg.servers[i].ip;
            ts->dns_chain_server_ports[i] = dns_cfg.servers[i].port;
        }
    }
    ts->domain_resolver_node.instance = ts->domain_resolver_tunnel;
    return true;
}

/*
 * Chain DNS only helps when its query lines reach the route the user meant.
 * Classify one synthetic query line per configured server with the real rule
 * matchers (no payload: query lines are classified at Init) and say where it
 * lands, so a rule that captures it earlier, or a dns rule that can never
 * match, is visible at startup instead of silently changing the DNS route.
 */
static void routerCheckDnsChainRoute(router_tstate_t *ts)
{
    if (! ts->dns_chain_mode)
    {
        return;
    }

    line_t *probe = memoryAllocateZero(sizeof(line_t));
    for (uint32_t s = 0; s < ts->dns_chain_servers_count; ++s)
    {
        memoryZero(probe, sizeof(line_t));
        address_context_t *dest = &probe->routing_context.dest_ctx;
        addresscontextSetIpPortProtocol(dest, &ts->dns_chain_server_ips[s], ts->dns_chain_server_ports[s], IP_PROTO_UDP);
        addresscontextSetResolverOrigin(dest, true);

        router_lstate_t ls;
        routerLinestateInitialize(&ls);
        ls.datagram_input = true;

        router_match_ctx_t mctx = {.router_state = ts, .line = probe, .line_state = &ls};
        uint32_t           hit  = ts->rules_count;
        for (uint32_t ri = 0; ri < ts->rules_count && ! mctx.evaluation_failed; ++ri)
        {
            if (routerRuleMatches(&ts->rules[ri], &mctx))
            {
                hit = ri;
                break;
            }
        }
        bufferqueueDestroy(&ls.datagrams); // never filled; the full line-state destroy assumes chain-sized storage

        if (hit == ts->rules_count)
        {
            LOGW("Router: chain DNS queries to dns.servers[%u] match no rule and follow the default \"next\" route; "
                 "add a rule with \"protocol\": \"dns\" to choose their route",
                 (unsigned) s);
        }
        else if ((ts->rules[hit].protocol.wanted_flags & kAddressContextProtocolDns) == 0)
        {
            LOGW("Router: chain DNS queries to dns.servers[%u] are captured by rule %u (target \"%s\"), which does not "
                 "name \"protocol\": \"dns\"; make sure that route is meant for DNS",
                 (unsigned) s,
                 (unsigned) hit,
                 ts->rules[hit].target_node != NULL ? ts->rules[hit].target_node->name : "?");
        }
    }
    memoryFree(probe);
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

    if (! routerCreateInternalDomainResolver(t, node, settings))
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

    routerCheckDnsChainRoute(ts);
    return t;
}
