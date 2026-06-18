#pragma once

#include "structure.h"

/*
 * "network" matcher.
 *
 * Matches the connection's network type (e.g. "tcp", "udp", "icmp", or combined
 * "tcp,udp"). Parsing only for now; the match implementation is a stub that
 * returns true.
 */
router_field_parse_t routerNetworkParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index);
bool                 routerNetworkMatch(const router_rule_t *rule, const router_match_ctx_t *mctx);
void                 routerNetworkDestroy(router_rule_t *rule);
