#include "modules/destination_domain/destination_domain.h"

#include "loggers/network_logger.h"

router_field_parse_t routerDestinationDomainParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(rule_json, "destination-domain");
    if (value == NULL)
    {
        rule->destination_domain.present = false;
        return kRouterFieldAbsent;
    }

    if (! routerStringListParse(
            &rule->destination_domain.patterns, value, "Router->settings->rules[]->destination-domain"))
    {
        LOGW("Router: rule %u has an invalid \"destination-domain\" condition", (unsigned int) rule_index);
        return kRouterFieldError;
    }

    rule->destination_domain.present = true;
    return kRouterFieldPresent;
}

bool routerDestinationDomainMatch(const router_rule_t *rule, const router_match_ctx_t *mctx)
{
    if (! rule->destination_domain.present)
    {
        return true;
    }

    const address_context_t *dest = lineGetDestinationAddressContext(mctx->line);

    // Only a domain destination can match; an IP destination has no domain here.
    if (dest->domain == NULL || dest->domain_len == 0)
    {
        return false;
    }

    const uint8_t *host     = (const uint8_t *) dest->domain;
    uint32_t       host_len = (uint32_t) dest->domain_len;

    for (uint32_t i = 0; i < rule->destination_domain.patterns.count; ++i)
    {
        if (routerDomainMatches(rule->destination_domain.patterns.items[i], host, host_len))
        {
            return true;
        }
    }

    if (rule->destination_domain.geosite_lists_count == 0)
    {
        return false;
    }

    router_geosite_host_cache_t        local_geosite_host = {0};
    const router_geosite_host_cache_t *geosite_host       = &mctx->geosite_host;
    if (! geosite_host->ready)
    {
        routerGeositeHostCachePrepare(&local_geosite_host, host, host_len);
        geosite_host = &local_geosite_host;
    }

    for (uint32_t i = 0; i < rule->destination_domain.geosite_lists_count; ++i)
    {
        if (routerGeositeCompiledListMatchesPrepared(rule->destination_domain.geosite_lists[i], geosite_host))
        {
            return true;
        }
    }

    return false;
}

void routerDestinationDomainDestroy(router_rule_t *rule)
{
    routerStringListDestroy(&rule->destination_domain.patterns);
    if (rule->destination_domain.geosite_lists != NULL)
    {
        memoryFree(rule->destination_domain.geosite_lists);
        rule->destination_domain.geosite_lists = NULL;
    }
    rule->destination_domain.geosite_lists_count = 0;
    rule->destination_domain.present             = false;
}
