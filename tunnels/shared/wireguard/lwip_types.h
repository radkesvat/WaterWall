#pragma once
#include <stdbool.h>
#include <stdint.h>

/*
    Most of the code is taken and renamed, from the awesome projects wireguard-lwip and lwip

    Author of lwip:              Adam Dunkels  https://github.com/smartalock/wireguard-lwip
    Author of wireguard-lwip:    Daniel Hope   https://github.com/lwip-tcpip/lwip

    their license files are placed next to this file
*/

struct ip4_addr
{
    uint32_t addr;
};

typedef struct ip4_addr ip4_addr_t;

/** This is the aligned version of ip6_addr_t,
    used as local variable, on the stack, etc. */
struct ip6_addr
{
    uint32_t addr[4];
#if LWIP_IPV6_SCOPES
    uint8_t zone;
#endif /* LWIP_IPV6_SCOPES */
};

/** IPv6 address */
typedef struct ip6_addr ip6_addr_t;

/** @ingroup ipaddr
 * IP address types for use in ip_addr_t.type member.
 * @see tcp_new_ip_type(), udp_new_ip_type(), raw_new_ip_type().
 */

enum lwip_ip_addr_type
{
    /** IPv4 */
    kIpaddrTypeV4 = 0U,
    /** IPv6 */
    kIpaddrTypeV6 = 6U,
    /** IPv4+IPv6 ("dual-stack") */
    kIpaddrTypeAny = 46U
};

/**
 * @ingroup ipaddr
 * A union struct for both IP version's addresses.
 * ATTENTION: watch out for its size when adding IPv6 address scope!
 */
typedef struct ip_addr
{
    union {
        ip6_addr_t ip6;
        ip4_addr_t ip4;
    } u_addr;
    /** @ref lwip_ip_addr_type */
    uint8_t type;
} ip_addr_t;

typedef unsigned char err_t;
