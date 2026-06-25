#pragma once

#include "structure.h"

/*
 * "destination-port" matcher.
 *
 * Matches the connection's destination port against exact integer ports from
 * "destination-port" and one inclusive range from "destination-port-range".
 */
router_field_parse_t routerDestinationPortParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index);
bool                 routerDestinationPortMatch(const router_rule_t *rule, const router_match_ctx_t *mctx);
void                 routerDestinationPortDestroy(router_rule_t *rule);
