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

/**
 * Socket protocols supported by the address system.
 * Maps directly to standard IPPROTO values for compatibility.
 */
enum socket_address_protocol
{
    kSapTcp = IPPROTO_TCP, // TCP protocol
    kSapUdp = IPPROTO_UDP, // UDP protocol
};

/**
 * Complete network address context.
 * Represents either an IP address or domain name with associated metadata.
 * Used for storing and managing network endpoint information.
 */
typedef struct address_context_s
{
    ip_addr_t         ip_address;      // IP address in network byte order
    uint16_t             port;            // Port number in host byte order
    char                *domain;          // Domain name if applicable
    enum domain_strategy domain_strategy; // DNS resolution strategy
    uint8_t              domain_len;      // Length of domain name

    // Flags for address properties
    uint8_t domain_constant : 1; // True if domain points to constant memory
    uint8_t type_ip : 1;         // True for IP address, false for domain
    uint8_t proto_tcp : 1;       // TCP protocol enabled
    uint8_t proto_ucp : 1;       // UDP protocol enabled
    uint8_t proto_icmp : 1;      // ICMP protocol enabled
    uint8_t proto_packet : 1;    // Raw packet protocol enabled
} address_context_t;

// Helper Functions

/**
 * Port management functions
 */
static inline void addresscontextPortCopy(address_context_t *dest, address_context_t *source)
{
    dest->port = source->port;
}

static inline void addresscontextPortSet(address_context_t *dest, uint16_t port)
{
    dest->port = port;
}

/**
 * Domain name management functions
 * These functions handle dynamic and constant memory allocation for domain names
 */
static inline void addresscontextDomainSet(address_context_t *restrict scontext, const char *restrict domain,
                                           uint8_t len)
{
    if (scontext->domain != NULL)
    {
        if (scontext->domain_constant)
        {
            scontext->domain = memoryAllocate(256);
        }
    }
    else
    {
        scontext->domain = memoryAllocate(256);
    }
    scontext->domain_constant = false;
    memoryCopy(scontext->domain, domain, len);
    scontext->domain[len] = 0x0;
    scontext->domain_len  = len;
}

static inline void addresscontextDomainSetConstMem(address_context_t *restrict scontext, const char *restrict domain,
                                                   uint8_t len)
{
    if (scontext->domain != NULL && ! scontext->domain_constant)
    {
        memoryFree(scontext->domain);
    }
    scontext->domain_constant = true;
    scontext->domain          = (char *) domain;
    scontext->domain_len      = len;
    assert(scontext->domain[len] == 0x0);
}

static inline void addresscontextAddrCopy(address_context_t *dest, const address_context_t *const source)
{
    dest->domain_constant = source->domain_constant;
    dest->type_ip         = source->type_ip;
    dest->proto_tcp       = source->proto_tcp;
    dest->proto_ucp       = source->proto_ucp;
    dest->proto_icmp      = source->proto_icmp;
    dest->proto_packet    = source->proto_packet;

    if (dest->type_ip)
    {
        dest->ip_address = source->ip_address;
    }
    else
    {
        if (source->domain != NULL)
        {
            if (source->domain_constant)
            {
                addresscontextDomainSetConstMem(dest, source->domain, source->domain_len);
            }
            else
            {
                addresscontextDomainSet(dest, source->domain, source->domain_len);
            }
        }
    }
}

/**
 * Address conversion functions
 * Convert between different address representation formats
 */

// Helper function to copy sockaddr_in or sockaddr_in6 to ip_addr_t
static inline void sockaddrToIpAddressCopy(const sockaddr_u *src, ip_addr_t *dest)
{
    assert(src != NULL && dest != NULL);

    if (((const struct sockaddr *) src)->sa_family == AF_INET)
    {
        // Copy IPv4 address
        const struct sockaddr_in *src_in = (const struct sockaddr_in *) src;
        dest->u_addr.ip4.addr            = src_in->sin_addr.s_addr;
        dest->type                       = AF_INET;
    }
    else if (((const struct sockaddr *) src)->sa_family == AF_INET6)
    {
        // Copy IPv6 address
        const struct sockaddr_in6 *src_in6 = (const struct sockaddr_in6 *) src;
        memcpy(&dest->u_addr.ip6, &src_in6->sin6_addr.s6_addr, sizeof(dest->u_addr.ip6));
        dest->type = AF_INET6;
    }
}

static inline sockaddr_u addresscontextToSockAddr(const address_context_t *context)
{
    sockaddr_u addr;
    assert(context->type_ip);
    if (context->ip_address.type == AF_INET)
    {
        struct sockaddr_in *addr_in = (struct sockaddr_in *) &addr;
        addr_in->sin_family         = AF_INET;
        addr_in->sin_port           = htons(context->port);
        addr_in->sin_addr.s_addr    = context->ip_address.u_addr.ip4.addr;
        return addr;
    }
    if (context->ip_address.type == AF_INET6)
    {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *) &addr;
        addr_in6->sin6_family         = AF_INET6;
        addr_in6->sin6_port           = htons(context->port);
        memcpy(&addr_in6->sin6_addr.s6_addr, &context->ip_address.u_addr.ip6, sizeof(addr_in6->sin6_addr.s6_addr));

        return addr;
    }
    assert(false); // not valid ip type
    return (sockaddr_u){0};
}

static void addresscontextSetIpPort(address_context_t *restrict scontext, const char *host, int port)
{

    sockaddr_u temp = {0};
    sockaddrSetIpPort(&temp, host, port);
    sockaddrToIpAddressCopy(&temp, &scontext->ip_address);
    addresscontextPortSet(scontext, ntohs(port));
}

/**
 * IP version detection and validation
 */
static inline int getIpVersion(char *host)
{
    if (isIPVer4(host))
    {
        return AF_INET;
    }
    if (isIPVer6(host))
    {
        return AF_INET6;
    }
    return 0; // not valid ip
}
