#pragma once

#include "structure.h"

/*
 * "source-port" matcher.
 *
 * Matches the connection's source port against exact integer ports from
 * "source-port" and one inclusive range from "source-port-range".
 */
router_field_parse_t routerSourcePortParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index);
bool                 routerSourcePortMatch(const router_rule_t *rule, const router_match_ctx_t *mctx);
void                 routerSourcePortDestroy(router_rule_t *rule);
