#include "modules/source_ips/source_ips.h"

#include "loggers/network_logger.h"

router_field_parse_t routerSourceIpsParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(rule_json, "source-ips");
    if (value == NULL)
    {
        rule->source_ips.present = false;
        return kRouterFieldAbsent;
    }

    if (! routerStringListParse(&rule->source_ips.patterns, value, "Router->settings->rules[]->source-ips"))
    {
        LOGW("Router: rule %u has an invalid \"source-ips\" condition", (unsigned int) rule_index);
        return kRouterFieldError;
    }

    if (! routerIpRangesParse(&rule->source_ips.patterns,
                              &rule->source_ips.ranges,
                              &rule->source_ips.ranges_count,
                              "Router->settings->rules[]->source-ips"))
    {
        return kRouterFieldError;
    }

    if (! routerGeoipCodesParse(&rule->source_ips.patterns,
                                &rule->source_ips.geoip_codes,
                                &rule->source_ips.geoip_codes_count,
                                "Router->settings->rules[]->source-ips"))
    {
        return kRouterFieldError;
    }

    rule->source_ips.present = true;
    return kRouterFieldPresent;
}

bool routerSourceIpsMatch(const router_rule_t *rule, const router_match_ctx_t *mctx)
{
    // A condition that is not configured does not constrain the rule.
    if (! rule->source_ips.present)
    {
        return true;
    }

    const address_context_t *src = lineGetSourceAddressContext(mctx->line);
    return routerIpRangesMatch(src, rule->source_ips.ranges, rule->source_ips.ranges_count) ||
           routerGeoipCodesMatch(mctx->router_state,
                                 src,
                                 rule->source_ips.geoip_codes,
                                 rule->source_ips.geoip_codes_count);
}

void routerSourceIpsDestroy(router_rule_t *rule)
{
    routerStringListDestroy(&rule->source_ips.patterns);
    if (rule->source_ips.ranges != NULL)
    {
        memoryFree(rule->source_ips.ranges);
        rule->source_ips.ranges = NULL;
    }
    rule->source_ips.ranges_count = 0;
    routerGeoipCodesDestroy(&rule->source_ips.geoip_codes, &rule->source_ips.geoip_codes_count);
    rule->source_ips.present      = false;
}
