#pragma once

#include "structure.h"

/*
 * "network" matcher.
 *
 * Matches a rule's requested network types against the saved incoming offer.
 */
router_field_parse_t routerNetworkParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index);
uint8_t              routerNetworkOffer(const address_context_t *dest);
bool                 routerNetworkMatch(const router_rule_t *rule, router_match_ctx_t *mctx);
void                 routerNetworkDestroy(router_rule_t *rule);
