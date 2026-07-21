#include "structure.h"

#include "loggers/network_logger.h"

static bool domainresolverParseStrategy(domainresolver_tstate_t *ts, const cJSON *settings)
{
    const cJSON *strategy_json = cJSON_GetObjectItemCaseSensitive(settings, "strategy");

    if (strategy_json == NULL)
    {
        ts->strategy = GSTATE.domain_strategy;
        return true;
    }

    if (cJSON_IsString(strategy_json) && strategy_json->valuestring != NULL &&
        stricmp(strategy_json->valuestring, "core-settings") == 0)
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
    if (UNLIKELY(t == NULL))
    {
        return NULL;
    }

    t->fnInitU    = &domainresolverTunnelUpStreamInit;
    t->fnEstU     = &domainresolverTunnelUpStreamEst;
    t->fnFinU     = &domainresolverTunnelUpStreamFinish;
    t->fnPayloadU = &domainresolverTunnelUpStreamPayload;
    t->fnPauseU   = &domainresolverTunnelUpStreamPause;
    t->fnResumeU  = &domainresolverTunnelUpStreamResume;

    t->fnInitD    = &domainresolverTunnelDownStreamInit;
    t->fnEstD     = &domainresolverTunnelDownStreamEst;
    t->fnFinD     = &domainresolverTunnelDownStreamFinish;
    t->fnPayloadD = &domainresolverTunnelDownStreamPayload;
    t->fnPauseD   = &domainresolverTunnelDownStreamPause;
    t->fnResumeD  = &domainresolverTunnelDownStreamResume;

    t->onStop    = &domainresolverTunnelOnStop;
    t->onDestroy = &domainresolverTunnelDestroy;

    domainresolver_tstate_t *ts       = tunnelGetState(t);
    const cJSON             *settings = node->node_settings_json;

    ts->strategy                  = GSTATE.domain_strategy;
    ts->verbose                   = false;
    ts->use_line_strategy         = false;
    ts->allow_missing_destination = false;

    if (settings != NULL && ! cJSON_IsObject(settings))
    {
        LOGF("JSON Error: DomainResolver->settings must be an object when provided");
        tunnelDestroy(t);
        return NULL;
    }

    if (settings != NULL)
    {
        getBoolFromJsonObjectOrDefault(&ts->verbose, settings, "verbose", false);
        if (! domainresolverParseStrategy(ts, settings))
        {
            tunnelDestroy(t);
            return NULL;
        }
    }

    return t;
}
