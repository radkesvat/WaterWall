#pragma once

#include "structure.h"

#include "protocol_sniff.h"

/*
 * "protocol" matcher.
 *
 * Matches optional application-protocol flags detected by Router from the first
 * upstream payload and stored on dest_ctx.optional_flags.
 */
typedef protocol_sniff_result_t (*router_protocol_sniff_fn)(const uint8_t *payload, uint32_t payload_len);

typedef struct router_protocol_descriptor_s
{
    const char              *name;
    uint32_t                 flag;
    router_protocol_sniff_fn sniff;
} router_protocol_descriptor_t;

const router_protocol_descriptor_t *routerProtocolDescriptors(uint32_t *out_count);
const router_protocol_descriptor_t *routerProtocolFindDescriptorByName(const char *name);

router_field_parse_t routerProtocolParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index);
bool                 routerProtocolMatch(const router_rule_t *rule, const router_match_ctx_t *mctx);
void                 routerProtocolDestroy(router_rule_t *rule);
