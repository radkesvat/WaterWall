#pragma once

#include "structure.h"

#include "wwapi.h"

/*
 * "protocol" matcher.
 *
 * Matches optional application-protocol flags detected by Router from the first
 * upstream payload and stored on dest_ctx.optional_flags. "dns" also matches a
 * resolver-generated query line (kAddressContextRouteFlagResolverOrigin), which
 * is classified during Init without sniffing.
 */
typedef generic_sniffer_result_t (*router_generic_sniffer_fn)(const uint8_t *payload, uint32_t payload_len);

typedef struct router_protocol_descriptor_s
{
    const char              *name;
    uint32_t                 flag;
    router_generic_sniffer_fn sniff;
    bool                      datagram_only; // sniff only UDP-only lines; never matches by sniffing elsewhere
} router_protocol_descriptor_t;

const router_protocol_descriptor_t *routerProtocolDescriptors(uint32_t *out_count);
const router_protocol_descriptor_t *routerProtocolFindDescriptorByName(const char *name);
// Union of the flags of every datagram-only protocol (they never match on stream lines).
uint32_t                            routerProtocolDatagramOnlyMask(void);

router_field_parse_t routerProtocolParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index);
bool                 routerProtocolMatch(const router_rule_t *rule, router_match_ctx_t *mctx);
void                 routerProtocolDestroy(router_rule_t *rule);
