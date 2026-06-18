#pragma once

#include "structure.h"

/*
 * "username" matcher.
 *
 * Matches the authenticated username / user identifier attached to the line
 * against a list of usernames. Parsing only for now; the match implementation is
 * a stub that returns true.
 */
router_field_parse_t routerUsernameParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index);
bool                 routerUsernameMatch(const router_rule_t *rule, const router_match_ctx_t *mctx);
void                 routerUsernameDestroy(router_rule_t *rule);
