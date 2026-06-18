#pragma once

#include "structure.h"

/*
 * "source-ips" matcher.
 *
 * Matches the connection's source address against a list of CIDR ranges or geo
 * rules (e.g. "0.0.0.0/8", "fc00::/7", "geoip:ir"). Parsing only for now; the
 * match implementation is a stub that returns true.
 */
router_field_parse_t routerSourceIpsParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index);
bool                 routerSourceIpsMatch(const router_rule_t *rule, const router_match_ctx_t *mctx);
void                 routerSourceIpsDestroy(router_rule_t *rule);
