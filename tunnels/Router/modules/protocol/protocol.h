#pragma once

#include "structure.h"

/*
 * "protocol" matcher.
 *
 * Matches the detected/known application protocol (e.g. "http", "tls", "quic",
 * "bittorrent"). Content-based detection can use mctx->payload. Parsing only for
 * now; the match implementation is a stub that returns true.
 */
router_field_parse_t routerProtocolParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index);
bool                 routerProtocolMatch(const router_rule_t *rule, const router_match_ctx_t *mctx);
void                 routerProtocolDestroy(router_rule_t *rule);
