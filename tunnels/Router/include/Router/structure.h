#pragma once

#include "wwapi.h"

#include "common/geosite_types.h"

#include <maxminddb.h>

/*
 * Router
 * ------
 * A layer-4 rule-based router. It sits inside a chain like a middle tunnel and,
 * on the first upstream payload of each connection, evaluates an ordered list of
 * routing rules to decide where the connection should go:
 *
 *   - the first rule whose match conditions ALL succeed (logical AND) wins, and
 *     the connection is handed to that rule's "target" node;
 *   - if no rule matches, the connection continues to the node's top-level
 *     "next" (the default route).
 *
 * Rule targets are folded into the same chain during onChain so they get per-line
 * state slots and so their downstream traffic returns through us. Just like
 * SniffRouter, the decision is deferred to the first payload and the buffered
 * bytes are replayed to the chosen branch with no loss; deferring the decision
 * keeps a payload window available for content-based matchers (e.g. "protocol").
 *
 * Each supported rule field has its own matcher/parser module under modules/.
 * Each module owns its config struct (stored inside router_rule_t) and exposes a
 * uniform parse/match/destroy interface.
 */

enum router_route_e
{
    kRouterRouteUndecided = 0,
    kRouterRouteTarget    = 1,
    kRouterRouteDefault   = 2
};

enum router_classify_result_e
{
    kRouterClassifyNeedMore = 0,
    kRouterClassifyDefault  = 1,
    kRouterClassifyTarget   = 2
};

typedef enum router_sniff_result_e
{
    kRouterSniffDone     = 0,
    kRouterSniffNeedMore = 1
} router_sniff_result_t;

enum
{
    kRouterSniffHttp1 = 1U << 0U,
    kRouterSniffTls   = 1U << 1U
};

enum
{
    kRouterAttributeHttpUpgradePresent = 1U << 0U
};

// Result of parsing a single rule field from the rule JSON object.
typedef enum router_field_parse_e
{
    kRouterFieldAbsent  = 0, // the field key was not present in the rule
    kRouterFieldPresent = 1, // the field key was present and parsed successfully
    kRouterFieldError   = 2  // the field key was present but its value was invalid
} router_field_parse_t;

// Shared "string or array of strings" value used by most matcher configs to
// hold the raw configured patterns.
typedef struct router_string_list_s
{
    char   **items;
    uint32_t count;
} router_string_list_t;

// Parsed CIDR / single-IP entry used by the source-ips and destination-ip
// matchers. A single IP (no prefix) is stored as a host route (/32 or /128).
typedef struct router_ip_range_s
{
    ip_addr_t ip;     // base address
    ip_addr_t mask;   // subnet mask
    uint8_t   family; // 4 or 6
} router_ip_range_t;

// Parsed ISO-3166 alpha-2 country code from a geoip:<cc> token.
typedef struct router_geoip_code_s
{
    char code[3]; // uppercase two-letter code plus NUL
} router_geoip_code_t;

typedef struct router_geosite_domain_key_s
{
    const char *value;
    uint32_t    len;
    hash_t      hash;
} router_geosite_domain_key_t;

static inline hash_t routerGeositeHashBytes(const char *value, uint32_t len)
{
    return calcHashBytesSeed(value, len, 0);
}

static inline uint64_t routerGeositeDomainKeyHash(const router_geosite_domain_key_t *key)
{
    return key->hash;
}

static inline bool routerGeositeDomainKeyEquals(const router_geosite_domain_key_t *left,
                                                const router_geosite_domain_key_t *right)
{
    return left->len == right->len && memoryCompare(left->value, right->value, left->len) == 0;
}

static inline bool routerStringEqualsIgnoreCase(const char *value, const char *expected)
{
    uint32_t i = 0;
    while (value[i] != '\0' && expected[i] != '\0')
    {
        if (asciiLower((uint8_t) value[i]) != (uint8_t) expected[i])
        {
            return false;
        }
        ++i;
    }
    return value[i] == '\0' && expected[i] == '\0';
}

static inline void routerGeositeDomainKeyDrop(router_geosite_domain_key_t *key)
{
    if (key->value != NULL)
    {
        memoryFree((void *) key->value);
    }
    key->value = NULL;
    key->len   = 0;
    key->hash  = 0;
}

#define i_type     router_geosite_domain_set_t  // NOLINT
#define i_key      router_geosite_domain_key_t  // NOLINT
#define i_hash     routerGeositeDomainKeyHash   // NOLINT
#define i_eq       routerGeositeDomainKeyEquals // NOLINT
#define i_keydrop  routerGeositeDomainKeyDrop   // NOLINT
#define i_no_clone                              // NOLINT
#include "stc/hset.h"
#undef i_no_clone
#undef i_keydrop
#undef i_eq
#undef i_hash
#undef i_key
#undef i_type

#include "stc/cregex.h"

typedef struct router_geosite_compiled_list_s
{
    char *name;

    /*
     * Shared by all workers after Router creation. Runtime matching treats
     * these STC sets as immutable and only calls contains()/read helpers. If a
     * future STC update adds read-side mutation, caching, or lazy maintenance to
     * lookup APIs, GeoSite matching must add synchronization or switch to an
     * explicitly immutable representation.
     */
    router_geosite_domain_set_t full_domains;
    router_geosite_domain_set_t root_domains;

    char   **plain_patterns;
    uint32_t plain_patterns_count;

    cregex  *regex_patterns;
    uint32_t regex_patterns_count;
} router_geosite_compiled_list_t;

typedef struct router_geosite_host_cache_s
{
    bool     ready;
    bool     valid;
    char     host[UINT8_MAX + 1U];
    uint32_t host_len;
    uint8_t  suffix_offsets[UINT8_MAX];
    uint32_t suffix_offsets_count;
} router_geosite_host_cache_t;

// Parsed single port or inclusive port range used by the port matchers.
typedef struct router_port_range_s
{
    uint16_t low;
    uint16_t high;
} router_port_range_t;

// Bit flags for the "network" matcher, mapped from address_context protocol bits.
enum
{
    kRouterNetworkTcp    = 1U << 0U,
    kRouterNetworkUdp    = 1U << 1U,
    kRouterNetworkIcmp   = 1U << 2U,
    kRouterNetworkPacket = 1U << 3U
};

// --- per-field matcher configuration (one struct per supported rule field) ---

typedef struct router_match_source_ips_s
{
    bool                 present;
    router_string_list_t patterns; // raw IP/CIDR and geoip:<cc> patterns
    router_ip_range_t   *ranges;   // parsed CIDR / single-IP ranges (geoip excluded)
    uint32_t             ranges_count;
    router_geoip_code_t *geoip_codes; // parsed geoip:<cc> country codes
    uint32_t             geoip_codes_count;
} router_match_source_ips_t;

typedef struct router_match_source_port_s
{
    bool                 present;
    router_port_range_t *ranges; // exact ports plus optional source-port-range
    uint32_t             ranges_count;
} router_match_source_port_t;

typedef struct router_match_network_s
{
    bool                 present;
    router_string_list_t values; // raw tokens: tcp / udp / icmp, possibly combined "tcp,udp"
    uint8_t              wanted; // OR of kRouterNetwork* flags
} router_match_network_t;

typedef struct router_match_protocol_s
{
    bool                 present;
    router_string_list_t values;       // detected protocol such as http1 / tls / bittorrent
    uint32_t             wanted_flags; // OR of kAddressContextProtocol* flags
} router_match_protocol_t;

typedef struct router_match_attributes_s
{
    bool     present;
    uint32_t count;
    uint32_t required_flags;
} router_match_attributes_t;

typedef struct router_match_destination_ip_s
{
    bool                 present;
    router_string_list_t patterns; // raw IP/CIDR and geoip:<cc> patterns
    router_ip_range_t   *ranges;   // parsed CIDR / single-IP ranges (geoip excluded)
    uint32_t             ranges_count;
    router_geoip_code_t *geoip_codes; // parsed geoip:<cc> country codes
    uint32_t             geoip_codes_count;
} router_match_destination_ip_t;

typedef struct router_match_destination_domain_s
{
    bool                             present;
    router_string_list_t             patterns;      // domains or geosite:xx rules
    router_geosite_compiled_list_t **geosite_lists; // compiled handles for geosite:xx rules
    uint32_t                         geosite_lists_count;
} router_match_destination_domain_t;

typedef struct router_match_username_s
{
    bool                 present;
    router_string_list_t values; // authenticated usernames / user identifiers
} router_match_username_t;

typedef struct router_match_password_s
{
    bool                 present;
    router_string_list_t values; // authenticated raw passwords
} router_match_password_t;

typedef struct router_match_destination_port_s
{
    bool                 present;
    router_port_range_t *ranges; // exact ports plus optional destination-port-range
    uint32_t             ranges_count;
} router_match_destination_port_t;

// One routing rule: a target node plus the AND-combined match conditions.
typedef struct router_rule_s
{
    node_t   *target_node;   // resolved during config parsing
    tunnel_t *target_tunnel; // bound during onChain

    router_match_source_ips_t         source_ips;
    router_match_source_port_t        source_port;
    router_match_network_t            network;
    router_match_protocol_t           protocol;
    router_match_attributes_t         attributes;
    router_match_destination_ip_t     destination_ip;
    router_match_destination_domain_t destination_domain;
    router_match_username_t           username;
    router_match_password_t           password;
    router_match_destination_port_t   destination_port;
} router_rule_t;

typedef struct router_tstate_s
{
    node_t                         domain_resolver_node;
    tunnel_t                      *domain_resolver_tunnel;
    router_rule_t                  *rules;
    uint32_t                        rules_count;
    char                           *geoip_db_path;
    MMDB_s                          geoip_db;
    bool                            geoip_db_opened;
    char                           *geosite_db_path;
    router_geosite_compiled_list_t *geosite_lists;
    uint32_t                        geosite_lists_count;
    uint8_t                         sniffing_modes;
    bool                            sniff_even_if_domain_is_already_provided;
    bool                            resolve_domains;
    bool                            needs_http_upgrade_attribute;
    uint32_t                        needed_protocols;
} router_tstate_t;

typedef struct router_lstate_s
{
    sbuf_t   *pending; // bytes buffered before a routing decision is made
    tunnel_t *target;  // selected rule tunnel; NULL means the default next branch
    uint8_t   decided; // enum router_route_e
    uint32_t  sniffed_attributes;
} router_lstate_t;

// Connection facts handed to matcher modules. Carries the line (for routing
// metadata such as source/destination address, ports, network type and user)
// and the buffered first-payload window (for content-based matchers).
typedef struct router_match_ctx_s
{
    router_tstate_t            *router_state;
    line_t                     *line;
    router_lstate_t            *line_state;
    const uint8_t              *payload;
    uint32_t                    payload_len;
    router_geosite_host_cache_t geosite_host;
} router_match_ctx_t;

typedef struct router_match_s
{
    enum router_classify_result_e result;
    tunnel_t                     *target;
} router_match_t;

WW_EXPORT void         routerTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *routerTunnelCreate(node_t *node);
WW_EXPORT api_result_t routerTunnelApi(tunnel_t *instance, sbuf_t *message);

// --- config parsing / evaluation (common) ---
bool                  routerLoadRules(router_tstate_t *ts, node_t *node, const cJSON *settings);
bool                  routerLoadSniffing(router_tstate_t *ts, const cJSON *settings);
void                  routerRuleTableDestroy(router_tstate_t *ts);
router_match_t        routerClassify(router_tstate_t *ts, const router_match_ctx_t *mctx);
router_sniff_result_t routerSniffBeforeClassify(router_tstate_t *ts, const router_match_ctx_t *mctx);

// Shared "string or array of strings" parser used by matcher modules.
bool routerStringListParse(router_string_list_t *list, const cJSON *value_json, const char *json_path);
void routerStringListDestroy(router_string_list_t *list);

// --- shared match helpers (common/match_helpers.c) ---

// Parse a list of IP / CIDR patterns into numeric ranges. "geoip:" entries are
// skipped here and parsed separately by routerGeoipCodesParse(). A single IP
// without a prefix is treated as a host route (/32 for IPv4, /128 for IPv6).
bool routerIpRangesParse(const router_string_list_t *patterns, router_ip_range_t **out_ranges, uint32_t *out_count,
                         const char *json_path);
bool routerIpRangesMatch(const address_context_t *ctx, const router_ip_range_t *ranges, uint32_t count);
bool routerGeoipCodesParse(const router_string_list_t *patterns, router_geoip_code_t **out_codes, uint32_t *out_count,
                           const char *json_path);
void routerGeoipCodesDestroy(router_geoip_code_t **codes, uint32_t *count);
bool routerGeoipCodesMatch(router_tstate_t *ts, const address_context_t *ctx, const router_geoip_code_t *codes,
                           uint32_t count);
bool routerRuleTableNeedsGeoip(const router_tstate_t *ts);
bool routerGeoipOpenIfNeeded(router_tstate_t *ts, const cJSON *settings);
void routerGeoipClose(router_tstate_t *ts);
bool routerRuleTableNeedsGeosite(const router_tstate_t *ts);
bool routerGeositeOpenIfNeeded(router_tstate_t *ts, const cJSON *settings);
void routerGeositeClose(router_tstate_t *ts);
bool routerGeositeNormalizeHost(const uint8_t *host, uint32_t host_len, char *out, uint32_t *out_len);
void routerGeositeHostCachePrepare(router_geosite_host_cache_t *cache, const uint8_t *host, uint32_t host_len);
uint32_t routerGeositeBuildSuffixOffsets(const char *host, uint32_t host_len, uint8_t *offsets,
                                         uint32_t offsets_capacity);
bool routerGeositeCompiledListMatches(const router_geosite_compiled_list_t *list, const char *host, uint32_t host_len);
bool routerGeositeCompiledListMatchesPrepared(const router_geosite_compiled_list_t *list,
                                              const router_geosite_host_cache_t    *host);

// Parse JSON exact-port and inclusive-range fields into numeric ranges.
bool routerPortRangesParse(const cJSON *ports_json, const cJSON *range_json, router_port_range_t **out_ranges,
                           uint32_t *out_count, const char *ports_json_path, const char *range_json_path);
bool routerPortRangesMatch(uint16_t port, const router_port_range_t *ranges, uint32_t count);

// Parse network tokens (tcp/udp/icmp/packet, comma-combinable) into a bit mask.
bool routerNetworkMaskParse(const router_string_list_t *values, uint8_t *out_mask, const char *json_path);

// Case-insensitive domain match supporting exact, "*.suffix" and "*" patterns.
// "geosite:" patterns are compiled separately and never matched here.
bool routerDomainMatches(const char *pattern, const uint8_t *host, uint32_t host_len);

// --- matcher dispatcher (modules/matchers.c) ---
bool routerRuleParseConditions(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index,
                               uint32_t *out_present_count);
bool routerRuleMatches(const router_rule_t *rule, const router_match_ctx_t *mctx);
void routerRuleDestroyConditions(router_rule_t *rule);
bool routerIsKnownConditionKey(const char *key);

// --- line state ---
void routerLinestateInitialize(router_lstate_t *ls);
void routerLinestateDestroy(line_t *l, router_lstate_t *ls);

// --- instance lifecycle ---
void routerTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void routerTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void routerTunnelOnPrepair(tunnel_t *t);
void routerTunnelOnStart(tunnel_t *t);
void routerTunnelOnStop(tunnel_t *t);

// --- upstream callbacks ---
void routerTunnelUpStreamInit(tunnel_t *t, line_t *l);
void routerTunnelUpStreamEst(tunnel_t *t, line_t *l);
void routerTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void routerTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void routerTunnelUpStreamPause(tunnel_t *t, line_t *l);
void routerTunnelUpStreamResume(tunnel_t *t, line_t *l);

// --- downstream callbacks ---
void routerTunnelDownStreamInit(tunnel_t *t, line_t *l);
void routerTunnelDownStreamEst(tunnel_t *t, line_t *l);
void routerTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void routerTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void routerTunnelDownStreamPause(tunnel_t *t, line_t *l);
void routerTunnelDownStreamResume(tunnel_t *t, line_t *l);
