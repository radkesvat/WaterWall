#pragma once

#include "wwapi.h"

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
 * uniform parse/match/destroy interface. The match logic is currently a stub
 * that returns true; only the architecture, parsing, and evaluation flow are
 * implemented so far.
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

// Result of parsing a single rule field from the rule JSON object.
typedef enum router_field_parse_e
{
    kRouterFieldAbsent  = 0, // the field key was not present in the rule
    kRouterFieldPresent = 1, // the field key was present and parsed successfully
    kRouterFieldError   = 2  // the field key was present but its value was invalid
} router_field_parse_t;

// Shared "string or array of strings" value, used by most matcher configs to
// hold the raw configured patterns until real matching logic is implemented.
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
    router_string_list_t patterns; // raw patterns, including geoip rules (ignored)
    router_ip_range_t   *ranges;   // parsed CIDR / single-IP ranges (geoip excluded)
    uint32_t             ranges_count;
} router_match_source_ips_t;

typedef struct router_match_source_port_s
{
    bool                 present;
    router_port_range_t *ranges; // parsed single ports and ranges such as "1000-2000"
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
    router_string_list_t values; // detected protocol such as http / tls / quic
} router_match_protocol_t;

typedef struct router_match_attributes_s
{
    bool     present;
    uint32_t count; // reserved for future metadata-based matching (unused for now)
} router_match_attributes_t;

typedef struct router_match_destination_ip_s
{
    bool                 present;
    router_string_list_t patterns; // raw patterns, including geoip rules (ignored)
    router_ip_range_t   *ranges;   // parsed CIDR / single-IP ranges (geoip excluded)
    uint32_t             ranges_count;
} router_match_destination_ip_t;

typedef struct router_match_destination_domain_s
{
    bool                 present;
    router_string_list_t patterns; // domains or geosite:xx rules
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
    router_port_range_t *ranges; // parsed single ports and ranges such as "1000-2000"
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
    router_rule_t *rules;
    uint32_t       rules_count;
} router_tstate_t;

typedef struct router_lstate_s
{
    sbuf_t   *pending;       // bytes buffered before a routing decision is made
    tunnel_t *target;        // selected rule tunnel; NULL means the default next branch
    uint8_t   decided;       // enum router_route_e
    bool      next_finished; // finish already propagated to the chosen upstream branch
    bool      prev_finished; // finish already propagated downstream to prev
} router_lstate_t;

// Connection facts handed to matcher modules. Carries the line (for routing
// metadata such as source/destination address, ports, network type and user)
// and the buffered first-payload window (for content-based matchers).
typedef struct router_match_ctx_s
{
    line_t        *line;
    const uint8_t *payload;
    uint32_t       payload_len;
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
bool           routerLoadRules(router_tstate_t *ts, node_t *node, const cJSON *settings);
void           routerRuleTableDestroy(router_tstate_t *ts);
router_match_t routerClassify(router_tstate_t *ts, const router_match_ctx_t *mctx);

// Shared "string or array of strings" parser used by matcher modules.
bool routerStringListParse(router_string_list_t *list, const cJSON *value_json, const char *json_path);
void routerStringListDestroy(router_string_list_t *list);

// --- shared match helpers (common/match_helpers.c) ---

// Parse a list of IP / CIDR patterns into numeric ranges. "geoip:" entries are
// accepted but skipped (left for future implementation). A single IP without a
// prefix is treated as a host route (/32 for IPv4, /128 for IPv6).
bool routerIpRangesParse(const router_string_list_t *patterns, router_ip_range_t **out_ranges, uint32_t *out_count,
                         const char *json_path);
bool routerIpRangesMatch(const address_context_t *ctx, const router_ip_range_t *ranges, uint32_t count);

// Parse a JSON number/string/array of ports and ranges into numeric ranges.
bool routerPortRangesParse(const cJSON *value_json, router_port_range_t **out_ranges, uint32_t *out_count,
                           const char *json_path);
bool routerPortRangesMatch(uint16_t port, const router_port_range_t *ranges, uint32_t count);

// Parse network tokens (tcp/udp/icmp/packet, comma-combinable) into a bit mask.
bool routerNetworkMaskParse(const router_string_list_t *values, uint8_t *out_mask, const char *json_path);

// Case-insensitive domain match supporting exact, "*.suffix" and "*" patterns.
// "geosite:" patterns are accepted by callers but never matched here.
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
