#pragma once

#include "structure.h"

/*
 * "destination-port" matcher.
 *
 * Matches the connection's destination port against a list of single ports or
 * ranges (e.g. "53", "443", "1000-2000"). Parsing only for now; the match
 * implementation is a stub that returns true.
 */
router_field_parse_t routerDestinationPortParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index);
bool                 routerDestinationPortMatch(const router_rule_t *rule, const router_match_ctx_t *mctx);
void                 routerDestinationPortDestroy(router_rule_t *rule);
