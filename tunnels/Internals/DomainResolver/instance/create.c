#include "structure.h"

#include "loggers/network_logger.h"

static bool domainresolverParseStrategy(domainresolver_tstate_t *ts, const cJSON *settings)
{
    const cJSON *strategy_json = cJSON_GetObjectItemCaseSensitive(settings, "strategy");

    if (strategy_json == NULL || (cJSON_IsString(strategy_json) && strategy_json->valuestring != NULL &&
                                  stricmp(strategy_json->valuestring, "core-settings") == 0))
    {
        ts->strategy = GSTATE.domain_strategy;
        return true;
    }

    if (getDomainStrategyFromJson(strategy_json, &ts->strategy))
    {
        return true;
    }

    LOGF("JSON Error: DomainResolver->settings->strategy must be one of \"core-settings\", "
         "\"accept-dns-returned-order\", \"prefer-ipv4\", \"prefer-ipv6\", \"only-ipv4\", or \"only-ipv6\"");
    return false;
}

tunnel_t *domainresolverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(domainresolver_tstate_t), sizeof(domainresolver_lstate_t));
    if (! t)
    {
        return NULL;
    }

    t->fnInitU    = &domainresolverTunnelUpStreamInit;
    t->fnFinU     = &domainresolverTunnelUpStreamFinish;
    t->fnPayloadU = &domainresolverTunnelUpStreamPayload;
    t->fnPauseU   = &domainresolverTunnelUpStreamPause;
    t->fnResumeU  = &domainresolverTunnelUpStreamResume;

    t->fnEstD     = &domainresolverTunnelDownStreamEst;
    t->fnFinD     = &domainresolverTunnelDownStreamFinish;
    t->fnPayloadD = &domainresolverTunnelDownStreamPayload;
    t->fnPauseD   = &domainresolverTunnelDownStreamPause;
    t->fnResumeD  = &domainresolverTunnelDownStreamResume;

    t->onPrepare       = &domainresolverTunnelOnPrepare;
    t->onWorkerQuiesce = &domainresolverTunnelOnWorkerQuiesce;
    t->onWorkerStop    = &domainresolverTunnelOnWorkerStop;
    t->onDestroy       = &domainresolverTunnelOnDestroy;

    domainresolver_tstate_t *ts       = tunnelGetState(t);
    const cJSON             *settings = node->node_settings_json;

    if (settings != NULL && ! cJSON_IsObject(settings))
    {
        LOGF("JSON Error: DomainResolver->settings must be an object when provided");
        tunnelDestroy(t);
        return NULL;
    }

    getBoolFromJsonObjectOrDefault(&ts->verbose, settings, "verbose", false);
    if (! domainresolverParseStrategy(ts, settings))
    {
        tunnelDestroy(t);
        return NULL;
    }

    /* Flat DNS keys at this node's settings level. Embedded resolvers receive
     * only a strategy object, so they always stay in core mode. The DNS keys
     * are validated only when mode is "chain": without it this node behaves
     * exactly as before, even if an existing config reuses one of the names. */
    const cJSON *mode_json = settings != NULL ? cJSON_GetObjectItemCaseSensitive(settings, "mode") : NULL;
    const bool   wants_chain =
        mode_json != NULL && (! cJSON_IsString(mode_json) || stringCompare(mode_json->valuestring, "core") != 0);
    ts->mode = kDnsLineClientModeCore;
    if (wants_chain && ! dnslineclientConfigParse(settings, "DomainResolver->settings", &ts->mode, &ts->chain_cfg))
    {
        tunnelDestroy(t);
        return NULL;
    }

    if (ts->mode != kDnsLineClientModeChain && settings != NULL)
    {
        /* Chain-only keys without mode "chain" do nothing; say so, because the
         * user most likely meant chain DNS and is getting core DNS instead. */
        static const char *const kChainOnlyKeys[] = {"servers", "timeout-ms", "tries", "cache-size",
                                                     "min-ttl", "max-ttl", "fallback-to-core"};
        for (size_t i = 0; i < sizeof(kChainOnlyKeys) / sizeof(kChainOnlyKeys[0]); ++i)
        {
            if (cJSON_GetObjectItemCaseSensitive(settings, kChainOnlyKeys[i]) != NULL)
            {
                LOGW("DomainResolver: settings->%s is ignored because settings->mode is not \"chain\"; DNS uses "
                     "the core resolver",
                     kChainOnlyKeys[i]);
            }
        }
    }

    if (ts->mode == kDnsLineClientModeChain)
    {
        // Standalone chain mode: the user's chain after this node routes the query lines.
        ts->inject_owner = t;
        ts->inject       = &domainresolverChainInjectNext;
    }

    return t;
}
