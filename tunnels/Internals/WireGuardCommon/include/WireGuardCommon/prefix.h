#pragma once

#include "wwapi.h"

/* A zero-initialized table is empty. The caller owns the stored values and
 * synchronizes access. IPv4 and IPv6 have independent longest-prefix roots. */
typedef struct wireguard_prefix_node_s wireguard_prefix_node_t;
typedef struct wireguard_prefix_table_s
{
    wireguard_prefix_node_t *roots[2];
} wireguard_prefix_table_t;

/* Returns the number of leading mask bits, or -1 for an invalid address/mask pair. */
int wireguardPrefixLength(const ip_addr_t *ip, const ip_addr_t *mask);

/* An exclusive reservation rejects overlap with another owner's range. For
 * routing, equal prefixes prefer the lowest id. Repeated insertion is idempotent. */
bool  wireguardPrefixInsert(wireguard_prefix_table_t *table, const ip_addr_t *ip, const ip_addr_t *mask, size_t id,
                            void *value, bool exclusive);
void  wireguardPrefixRemove(wireguard_prefix_table_t *table, const ip_addr_t *ip, const ip_addr_t *mask, size_t id);
void *wireguardPrefixLookup(const wireguard_prefix_table_t *table, const ip_addr_t *ip);
void  wireguardPrefixDestroy(wireguard_prefix_table_t *table);
