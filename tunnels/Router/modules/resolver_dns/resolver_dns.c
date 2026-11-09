#include "modules/resolver_dns/resolver_dns.h"

#include "loggers/network_logger.h"

router_field_parse_t routerResolverDnsParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(rule_json, "resolver-dns");
    rule->resolver_dns = (router_match_resolver_dns_t) {0};
    if (value == NULL)
    {
        return kRouterFieldAbsent;
    }
    if (! cJSON_IsBool(value))
    {
        LOGF("Router: rule %u \"resolver-dns\" must be a boolean", (unsigned int) rule_index);
        return kRouterFieldError;
    }

    rule->resolver_dns.present = true;
    rule->resolver_dns.wanted  = cJSON_IsTrue(value);
    return kRouterFieldPresent;
}

bool routerResolverDnsMatch(const router_rule_t *rule, router_match_ctx_t *mctx)
{
    return ! rule->resolver_dns.present ||
           addresscontextIsResolverDns(lineGetDestinationAddressContext(mctx->line)) == rule->resolver_dns.wanted;
}

void routerResolverDnsDestroy(router_rule_t *rule)
{
    rule->resolver_dns = (router_match_resolver_dns_t) {0};
}
