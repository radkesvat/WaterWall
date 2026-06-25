#include "structure.h"

#include "loggers/network_logger.h"

#include "modules/attributes/attributes.h"
#include "modules/destination_domain/destination_domain.h"
#include "modules/destination_ip/destination_ip.h"
#include "modules/destination_port/destination_port.h"
#include "modules/network/network.h"
#include "modules/password/password.h"
#include "modules/protocol/protocol.h"
#include "modules/source_ips/source_ips.h"
#include "modules/source_port/source_port.h"
#include "modules/username/username.h"

/*
 * Matcher dispatcher. Each supported rule field is a self-contained module that
 * exposes a uniform parse/match/destroy interface operating on its own slice of
 * router_rule_t. This table is the single place that knows the full set of
 * matchers, mirroring AuthenticationServer's module dispatcher.
 */

typedef router_field_parse_t (*router_matcher_parse_fn)(router_rule_t *rule, const cJSON *rule_json,
                                                        uint32_t rule_index);
typedef bool (*router_matcher_match_fn)(const router_rule_t *rule, const router_match_ctx_t *mctx);
typedef void (*router_matcher_destroy_fn)(router_rule_t *rule);

typedef struct router_matcher_s
{
    const char               *name; // the JSON key, also used for logging
    router_matcher_parse_fn   parse;
    router_matcher_match_fn   match;
    router_matcher_destroy_fn destroy;
} router_matcher_t;

static const router_matcher_t kRouterMatchers[] = {
    {"source-ips", routerSourceIpsParse, routerSourceIpsMatch, routerSourceIpsDestroy},
    {"source-port", routerSourcePortParse, routerSourcePortMatch, routerSourcePortDestroy},
    {"network", routerNetworkParse, routerNetworkMatch, routerNetworkDestroy},
    {"protocol", routerProtocolParse, routerProtocolMatch, routerProtocolDestroy},
    {"attributes", routerAttributesParse, routerAttributesMatch, routerAttributesDestroy},
    {"destination-ip", routerDestinationIpParse, routerDestinationIpMatch, routerDestinationIpDestroy},
    {"destination-domain", routerDestinationDomainParse, routerDestinationDomainMatch, routerDestinationDomainDestroy},
    {"username", routerUsernameParse, routerUsernameMatch, routerUsernameDestroy},
    {"password", routerPasswordParse, routerPasswordMatch, routerPasswordDestroy},
    {"destination-port", routerDestinationPortParse, routerDestinationPortMatch, routerDestinationPortDestroy},
};

static const char *const kRouterKnownConditionAliases[] = {
    "source-port-range",
    "destination-port-range",
};

enum
{
    kRouterMatchersCount              = (int) (sizeof(kRouterMatchers) / sizeof(kRouterMatchers[0])),
    kRouterKnownConditionAliasesCount =
        (int) (sizeof(kRouterKnownConditionAliases) / sizeof(kRouterKnownConditionAliases[0]))
};

bool routerRuleParseConditions(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index,
                               uint32_t *out_present_count)
{
    uint32_t present = 0;

    for (int i = 0; i < kRouterMatchersCount; ++i)
    {
        switch (kRouterMatchers[i].parse(rule, rule_json, rule_index))
        {
        case kRouterFieldPresent:
            ++present;
            break;
        case kRouterFieldError:
            *out_present_count = present;
            return false;
        case kRouterFieldAbsent:
        default:
            break;
        }
    }

    *out_present_count = present;
    return true;
}

bool routerRuleMatches(const router_rule_t *rule, const router_match_ctx_t *mctx)
{
    // AND across every configured condition. Matchers for fields that are not
    // present in this rule return true and therefore do not constrain it.
    for (int i = 0; i < kRouterMatchersCount; ++i)
    {
        if (! kRouterMatchers[i].match(rule, mctx))
        {
            return false;
        }
    }
    return true;
}

void routerRuleDestroyConditions(router_rule_t *rule)
{
    for (int i = 0; i < kRouterMatchersCount; ++i)
    {
        kRouterMatchers[i].destroy(rule);
    }
}

bool routerIsKnownConditionKey(const char *key)
{
    for (int i = 0; i < kRouterMatchersCount; ++i)
    {
        if (stringCompare(kRouterMatchers[i].name, key) == 0)
        {
            return true;
        }
    }

    for (int i = 0; i < kRouterKnownConditionAliasesCount; ++i)
    {
        if (stringCompare(kRouterKnownConditionAliases[i], key) == 0)
        {
            return true;
        }
    }

    return false;
}
