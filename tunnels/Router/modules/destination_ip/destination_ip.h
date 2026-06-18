#pragma once

#include "structure.h"

/*
 * "destination-ip" matcher.
 *
 * Matches the connection's destination address against a list of CIDR ranges or
 * GeoIP country tokens (e.g. "0.0.0.0/8", "fc00::/7", "geoip:ir").
 */
router_field_parse_t routerDestinationIpParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index);
bool                 routerDestinationIpMatch(const router_rule_t *rule, const router_match_ctx_t *mctx);
void                 routerDestinationIpDestroy(router_rule_t *rule);
