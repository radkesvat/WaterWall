#pragma once

#include "wwapi.h"

#include "geosite.h"
#include "rule_types.h"
#include "sniffing.h"

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
    uint8_t   route;   // enum router_route_e
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
bool           routerRuleTableLoad(router_tstate_t *ts, node_t *node, const cJSON *settings);
void           routerRuleTableDestroy(router_tstate_t *ts);
router_match_t routerClassify(router_tstate_t *ts, router_match_ctx_t *mctx);

// --- geoip / geosite helpers that need router_tstate_t ---
bool routerGeoipCodesMatch(router_tstate_t *ts, const address_context_t *ctx, const router_geoip_code_t *codes,
                           uint32_t count);
bool routerRuleTableNeedsGeoip(const router_tstate_t *ts);
bool routerGeoipOpenIfNeeded(router_tstate_t *ts, const cJSON *settings);
void routerGeoipClose(router_tstate_t *ts);
bool routerRuleTableNeedsGeosite(const router_tstate_t *ts);
bool routerGeositeOpenIfNeeded(router_tstate_t *ts, const cJSON *settings);
void routerGeositeClose(router_tstate_t *ts);

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
