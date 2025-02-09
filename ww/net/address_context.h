#pragma once

#include "wlibc.h"
#include "wsocket.h"

/**
 * Network Address Management System
 * This header defines structures and functions for handling both IPv4 and IPv6 addresses,
 * as well as domain names in a unified way. It provides abstraction for different address types
 * and protocols used in network communications.
 */

/**
 * Domain name resolution strategy.
 * Defines how the system should handle DNS resolution when both IPv4 and IPv6 are available.
 */
enum domain_strategy
{
    kDsInvalid,    // Invalid or unspecified strategy
    kDsPreferIpV4, // Try IPv4 first, fallback to IPv6
    kDsPreferIpV6, // Try IPv6 first, fallback to IPv4
    kDsOnlyIpV4,   // Use only IPv4 addresses
    kDsOnlyIpV6    // Use only IPv6 addresses
};

enum address_context_type
{
    kAcDomain = 0x0,
    kAcIp     = 0x1
};

enum socket_address_protocol
{
    kSocketProtocolTcp,
    kSocketProtocolUdp,
    kSocketProtocolIcmp,
    kSocketProtocolPacket
};

/**
 * Complete network address context.
 * Represents either an IP address or domain name with associated metadata.
 * Used for storing and managing network endpoint information.
 */
typedef struct address_context_s
{
    ip_addr_t            ip_address;      // IP address in network byte order
    uint16_t             port;            // Port number in host byte order
    char                *domain;          // Domain name if applicable
    enum domain_strategy domain_strategy; // DNS resolution strategy
    uint8_t              domain_len;      // Length of domain name

    // Flags for address properties
    uint8_t domain_constant : 1; // True if domain points to constant memory, will not call free on <domain ptr>
    uint8_t type_ip : 1;         // True for IP address, false for domain
    uint8_t proto_tcp : 1;       // TCP protocol enabled
    uint8_t proto_ucp : 1;       // UDP protocol enabled
    uint8_t proto_icmp : 1;      // ICMP protocol enabled
    uint8_t proto_packet : 1;    // Raw packet protocol enabled
} address_context_t;

// Helper Functions

static inline bool addresscontextIsValid(const address_context_t *context)
{
    if (context->type_ip && ! ipAddrIsAny(&context->ip_address))
    {
        return true; // Valid IP address
    }
    if (context->domain != NULL && context->domain_len != 0)
    {
        return true; // Valid domain name
    }
    return false; // Neither IP nor domain is valid
}

/**
 * Port management functions
 */
static inline void addresscontextCopyPort(address_context_t *dest, address_context_t *source)
{
    dest->port = source->port;
}

static inline void addresscontextSetPort(address_context_t *dest, uint16_t port)
{
    dest->port = port;
}

/**
 * Domain name management functions
 * These functions handle dynamic and constant memory allocation for domain names
 */
static inline void addressContextDomainSet(address_context_t *restrict scontext, const char *restrict domain,
                                           uint8_t len)
{
    if (scontext->domain != NULL && ! scontext->domain_constant)
    {
        memoryFree(scontext->domain); // Free previously allocated memory
    }
    scontext->domain = memoryAllocate(256);

    memoryCopy(scontext->domain, domain, len);
    scontext->domain[len]     = '\0';
    scontext->domain_len      = len;
    scontext->domain_constant = false;

    scontext->type_ip = kAcDomain;
}

static inline void addressContextDomainSetConstMem(address_context_t *restrict scontext, const char *restrict domain,
                                                   uint8_t len)
{
    if (scontext->domain != NULL && ! scontext->domain_constant)
    {
        memoryFree(scontext->domain); // Free previously allocated memory
    }
    scontext->domain          = (char *) domain; // Point to constant memory
    scontext->domain_len      = len;
    scontext->domain_constant = true;      // Mark as constant memory
    assert(scontext->domain[len] == '\0'); // Ensure null-termination

    scontext->type_ip = kAcDomain;
}

static inline void addresscontextAddrCopy(address_context_t *dest, const address_context_t *const source)
{
    // Copy flags
    dest->domain_constant = source->domain_constant;
    dest->type_ip         = source->type_ip;
    dest->proto_tcp       = source->proto_tcp;
    dest->proto_ucp       = source->proto_ucp;
    dest->proto_icmp      = source->proto_icmp;
    dest->proto_packet    = source->proto_packet;

    // Copy port
    dest->port = source->port;

    // Copy IP address or domain
    if (dest->type_ip)
    {
        ipAddrCopy(dest->ip_address, source->ip_address);
    }
    else
    {
        if (source->domain != NULL)
        {
            if (source->domain_constant)
            {
                addressContextDomainSetConstMem(dest, source->domain, source->domain_len);
            }
            else
            {
                addressContextDomainSet(dest, source->domain, source->domain_len);
            }
        }
        else
        {
            dest->domain     = NULL;
            dest->domain_len = 0;
        }
    }
}

// Protocol flag management functions
static inline void addressContextEnableTcp(address_context_t *dest)
{
    dest->proto_tcp = true;
}

static inline void addressContextDisableTcp(address_context_t *dest)
{
    dest->proto_tcp = false;
}

static inline void addressContextEnableUdp(address_context_t *dest)
{
    dest->proto_ucp = true;
}

static inline void addressContextDisableUdp(address_context_t *dest)
{
    dest->proto_ucp = false;
}

static inline void addressContextEnableIcmp(address_context_t *dest)
{
    dest->proto_icmp = true;
}

static inline void addressContextDisableIcmp(address_context_t *dest)
{
    dest->proto_icmp = false;
}

static inline void addressContextEnablePacket(address_context_t *dest)
{
    dest->proto_packet = true;
}

static inline void addressContextDisablePacket(address_context_t *dest)
{
    dest->proto_packet = false;
}

static inline void addresscontextSetProtocol(address_context_t *dest, enum socket_address_protocol protocol)
{
    switch (protocol)
    {
        case kSocketProtocolTcp:
            addressContextEnableTcp(dest);
            break;
        case kSocketProtocolUdp:
            addressContextEnableUdp(dest);
            break;
        case kSocketProtocolIcmp:
            addressContextEnableIcmp(dest);
            break;
        case kSocketProtocolPacket:
            addressContextEnablePacket(dest);
            break;
        default:
            break;
    }
}

/**
 * IP address management functions
 */

static void addresscontextSetIp(address_context_t *restrict scontext, const ip_addr_t *restrict ip)
{
    scontext->ip_address = *ip;
    scontext->type_ip    = kAcIp;
}

static void addresscontextSetIpPort(address_context_t *restrict scontext, const ip_addr_t *restrict ip, uint16_t port)
{
    scontext->ip_address = *ip;
    scontext->port       = port;
    scontext->type_ip    = kAcIp;
}
/**
 * IP version detection and validation
 */
static inline int getIpVersion(char *host)
{
    if (isIPVer4(host))
    {
        return IPADDR_TYPE_V4;
    }
    if (isIPVer6(host))
    {
        return IPADDR_TYPE_V6;
    }
    return 0; // not valid ip
}

static inline void addressContextClearIp(address_context_t *ctx)
{
    ipAddrSetAny(false, &ctx->ip_address); // false means ipv4,  Set to zero IP address
    ctx->type_ip = kAcDomain;              // Mark as not an IP address
}

/**
 * Address conversion functions
 * Convert between different address representation formats
 */

// Helper function to copy sockaddr_in or sockaddr_in6 to ip_addr_t
static inline void sockaddrToIpAddressCopy(const sockaddr_u *src, ip_addr_t *dest)
{
    assert(src != NULL && dest != NULL);

    if (((const struct sockaddr *) src)->sa_family == IPADDR_TYPE_V4)
    {
        // Copy IPv4 address
        const struct sockaddr_in *src_in = (const struct sockaddr_in *) src;
        dest->u_addr.ip4.addr            = src_in->sin_addr.s_addr;
        dest->type                       = AF_INET;
    }
    else if (((const struct sockaddr *) src)->sa_family == IPADDR_TYPE_V6)
    {
        // Copy IPv6 address
        const struct sockaddr_in6 *src_in6 = (const struct sockaddr_in6 *) src;
        memoryCopy(&dest->u_addr.ip6, &src_in6->sin6_addr.s6_addr, sizeof(dest->u_addr.ip6));
        dest->type = AF_INET6;
    }
}

static inline sockaddr_u addresscontextToSockAddr(const address_context_t *context)
{
    sockaddr_u addr;
    assert(context->type_ip);
    if (context->ip_address.type == IPADDR_TYPE_V4)
    {
        struct sockaddr_in *addr_in = (struct sockaddr_in *) &addr;
        addr_in->sin_family         = AF_INET;
        addr_in->sin_port           = htons(context->port);
        addr_in->sin_addr.s_addr    = context->ip_address.u_addr.ip4.addr;
        return addr;
    }
    if (context->ip_address.type == IPADDR_TYPE_V4)
    {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *) &addr;
        addr_in6->sin6_family         = AF_INET6;
        addr_in6->sin6_port           = htons(context->port);
        memoryCopy(&addr_in6->sin6_addr.s6_addr, &context->ip_address.u_addr.ip6, sizeof(addr_in6->sin6_addr.s6_addr));

        return addr;
    }
    assert(false); // not valid ip type
    return (sockaddr_u){0};
}
