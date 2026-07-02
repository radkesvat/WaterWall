#pragma once

#include "geosite.h"

typedef enum router_field_parse_e
{
    kRouterFieldAbsent  = 0,
    kRouterFieldPresent = 1,
    kRouterFieldError   = 2
} router_field_parse_t;

typedef struct router_string_list_s
{
    char   **items;
    uint32_t count;
} router_string_list_t;

typedef struct router_ip_range_s
{
    ip_addr_t ip;
    ip_addr_t mask;
    uint8_t   family;
} router_ip_range_t;

typedef struct router_geoip_code_s
{
    char code[3];
} router_geoip_code_t;

typedef struct router_port_range_s
{
    uint16_t low;
    uint16_t high;
} router_port_range_t;

enum
{
    kRouterNetworkTcp    = 1U << 0U,
    kRouterNetworkUdp    = 1U << 1U,
    kRouterNetworkIcmp   = 1U << 2U,
    kRouterNetworkPacket = 1U << 3U
};

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

typedef struct router_match_source_ips_s
{
    bool                 present;
    router_string_list_t patterns;
    router_ip_range_t   *ranges;
    uint32_t             ranges_count;
    router_geoip_code_t *geoip_codes;
    uint32_t             geoip_codes_count;
} router_match_source_ips_t;

typedef struct router_match_source_port_s
{
    bool                 present;
    router_port_range_t *ranges;
    uint32_t             ranges_count;
} router_match_source_port_t;

typedef struct router_match_network_s
{
    bool                 present;
    router_string_list_t values;
    uint8_t              wanted;
} router_match_network_t;

typedef struct router_match_protocol_s
{
    bool                 present;
    router_string_list_t values;
    uint32_t             wanted_flags;
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
    router_string_list_t patterns;
    router_ip_range_t   *ranges;
    uint32_t             ranges_count;
    router_geoip_code_t *geoip_codes;
    uint32_t             geoip_codes_count;
} router_match_destination_ip_t;

typedef struct router_match_destination_domain_s
{
    bool                             present;
    router_string_list_t             patterns;
    router_geosite_compiled_list_t **geosite_lists;
    uint32_t                         geosite_lists_count;
} router_match_destination_domain_t;

typedef struct router_match_username_s
{
    bool                 present;
    router_string_list_t values;
} router_match_username_t;

typedef struct router_match_password_s
{
    bool                 present;
    router_string_list_t values;
} router_match_password_t;

typedef struct router_match_destination_port_s
{
    bool                 present;
    router_port_range_t *ranges;
    uint32_t             ranges_count;
} router_match_destination_port_t;

typedef struct router_rule_s
{
    node_t   *target_node;
    tunnel_t *target_tunnel;

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

bool routerStringListParse(router_string_list_t *list, const cJSON *value_json, const char *json_path);
void routerStringListDestroy(router_string_list_t *list);

bool routerIpRangesParse(const router_string_list_t *patterns, router_ip_range_t **out_ranges, uint32_t *out_count,
                         const char *json_path);
bool routerIpRangesMatch(const address_context_t *ctx, const router_ip_range_t *ranges, uint32_t count);
bool routerGeoipCodesParse(const router_string_list_t *patterns, router_geoip_code_t **out_codes, uint32_t *out_count,
                           const char *json_path);
void routerGeoipCodesDestroy(router_geoip_code_t **codes, uint32_t *count);
bool routerAuthenticatedCredentialsMatch(const router_rule_t *rule, const line_t *line);

bool routerPortRangesParse(const cJSON *ports_json, const cJSON *range_json, router_port_range_t **out_ranges,
                           uint32_t *out_count, const char *ports_json_path, const char *range_json_path);
bool routerPortRangesMatch(uint16_t port, const router_port_range_t *ranges, uint32_t count);
