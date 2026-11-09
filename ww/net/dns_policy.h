#pragma once

#include "address_context.h"
#include "cJSON.h"

/* Effective values are immutable after construction. Strings belong to the
 * policy; destroy only after every consumer has finished copying its settings. */
typedef enum dns_policy_mode_e
{
    kDnsPolicyModeNative = 0,
    kDnsPolicyModeDirect,
    kDnsPolicyModeChain
} dns_policy_mode_t;

typedef struct dns_policy_s
{
    bool                 supplied;
    bool                 resolve;
    dns_policy_mode_t    mode;
    enum domain_strategy strategy;
    char                *servers_csv;
    char                *dns_next;
} dns_policy_t;

typedef struct dns_policy_defaults_s
{
    bool                 resolve;
    enum domain_strategy strategy;
    enum domain_strategy core_strategy;
    bool                 require_dns_next;
    bool                 ipv4_only;
} dns_policy_defaults_t;

/* Consumers supply their defaults directly. Removed domain-strategy and
 * resolve-domains fields are rejected even when dns-behaviour is absent. */
bool dnsPolicyParseSettings(dns_policy_t *policy, const cJSON *settings, const dns_policy_defaults_t *defaults,
                            const char *path);
bool dnsPolicyParseFlat(dns_policy_t *policy, const cJSON *settings, const dns_policy_defaults_t *defaults,
                        const char *path);
bool dnsPolicyParseStrategy(const cJSON *value, enum domain_strategy core_strategy, enum domain_strategy *strategy);
bool dnsPolicyParseStrategyOverride(enum domain_strategy *strategy, const cJSON *settings, bool resolve_enabled,
                                    const char *path);
const char *dnsPolicyStrategyName(enum domain_strategy strategy);
void        dnsPolicyDestroy(dns_policy_t *policy);
cJSON      *dnsPolicyCreateResolverSettings(const dns_policy_t *policy);
