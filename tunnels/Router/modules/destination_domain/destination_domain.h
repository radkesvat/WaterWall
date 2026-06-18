#pragma once

#include "structure.h"

/*
 * "destination-domain" matcher.
 *
 * Matches the connection's destination domain against a list of domains or
 * geosite rules (e.g. "google.com", "geosite:cn"). Parsing only for now; the
 * match implementation is a stub that returns true.
 */
router_field_parse_t routerDestinationDomainParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index);
bool                 routerDestinationDomainMatch(const router_rule_t *rule, const router_match_ctx_t *mctx);
void                 routerDestinationDomainDestroy(router_rule_t *rule);
