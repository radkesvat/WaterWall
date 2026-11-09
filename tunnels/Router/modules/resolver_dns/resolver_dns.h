#pragma once

#include "structure.h"

/* Origin metadata available at Init; this matcher never inspects payload. */
router_field_parse_t routerResolverDnsParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index);
bool                 routerResolverDnsMatch(const router_rule_t *rule, router_match_ctx_t *mctx);
void                 routerResolverDnsDestroy(router_rule_t *rule);
