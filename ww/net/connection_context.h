#pragma once

#include "wlibc.h"
#include "wsocket.h"

// ============================================================================
// Data Types and Enumerations
// ============================================================================
/**
 * Network Address Management System
 * This header defines structures and functions for handling both IPv4 and IPv6 addresses,
 * as well as domain names in a unified way.
 */

/**
 * Domain name resolution strategy.
 */
enum domain_strategy
{
    kDsInvalid,    // Invalid or unspecified strategy
    kDsPreferIpV4, // Try IPv4 first, fallback to IPv6
    kDsPreferIpV6, // Try IPv6 first, fallback to IPv4
    kDsOnlyIpV4,   // Use only IPv4 addresses
    kDsOnlyIpV6    // Use only IPv6 addresses
};

enum connection_context_type
{
    kCCTypeDomain = 0x0,
    kCCTypeIp     = 0x1
};

enum socket_address_protocol
{
    kSocketProtocolTcp,
    kSocketProtocolUdp,
    kSocketProtocolIcmp,
    kSocketProtocolPacket
};

/**
 * Connction context provieds complete information about a connection. It can be used to connecto to somewhere.
 */
typedef struct connection_context_s
{
    ip_addr_t            ip_address;      // IP address in network byte order
    uint16_t             port;            // Port number in host byte order
    char                *domain;          // Domain name if applicable
    enum domain_strategy domain_strategy; // DNS resolution strategy
    uint8_t              domain_len;      // Length of domain name

    // Flags for address properties
    uint8_t type_ip : 1;         // True for IP address, false for domain
    uint8_t proto_tcp : 1;       // TCP protocol enabled
    uint8_t proto_ucp : 1;       // UDP protocol enabled
    uint8_t proto_icmp : 1;      // ICMP protocol enabled
    uint8_t proto_packet : 1;    // Raw packet protocol enabled
    uint8_t domain_constant : 1; // True if domain points to constant memory, will not free it

} connection_context_t;

// ============================================================================
// Initialization and Reset Helpers
// ============================================================================
/**
 * @brief Initialize an address context structure.
 *
 * Sets the structure to zeros and defaults type to domain.
 */
static inline void addressContextInit(connection_context_t *ctx)
{
    // Set all fields to zero then default type as domain
    memset(ctx, 0, sizeof(*ctx));
    ctx->type_ip = kCCTypeDomain;
}

/**
 * @brief Reset an address context structure.
 *
 * Frees domain memory if allocated (non-constant) and resets all fields.
 */
static inline void addressContextReset(connection_context_t *ctx)
{
    if (ctx->domain != NULL && ! ctx->domain_constant)
    {
        memoryFree(ctx->domain);
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->type_ip = kCCTypeDomain;
}

// ============================================================================
// Validation Helper
// ============================================================================
/**
 * @brief Check whether the address context contains a valid IP or domain.
 *
 * @param context The address context to verify.
 * @return true if valid; false otherwise.
 */
static inline bool addresscontextIsValid(const connection_context_t *context)
{
    if (context->type_ip && ! ipAddrIsAny(&context->ip_address))
    {
        return true; // Valid IP address
    }
    if (context->domain != NULL && context->domain_len != 0)
    {
        return true; // Valid domain name
    }
    return false;
}

// ============================================================================
// Port Management Functions
// ============================================================================
/**
 * @brief Copy port from source to destination context.
 */
static inline void addresscontextCopyPort(connection_context_t *dest, connection_context_t *source)
{
    dest->port = source->port;
}

/**
 * @brief Set the port for an address context.
 */
static inline void addresscontextSetPort(connection_context_t *dest, uint16_t port)
{
    dest->port = port;
}

// ============================================================================
// Domain Name Management Functions
// ============================================================================
/**
 * @brief Set a domain for the address context (dynamic memory).
 */
static inline void addressContextDomainSet(connection_context_t *restrict scontext, const char *restrict domain,
                                           uint8_t len)
{
    if (scontext->domain != NULL && ! scontext->domain_constant)
    {
        memoryFree(scontext->domain); // Free previous allocation
    }
    scontext->domain = memoryAllocate(256);
    memoryCopy(scontext->domain, domain, len);
    scontext->domain[len]     = '\0';
    scontext->domain_len      = len;
    scontext->domain_constant = false;
    scontext->type_ip         = kCCTypeDomain;
}

/**
 * @brief Set a domain for the address context using constant memory.
 */
static inline void addressContextDomainSetConstMem(connection_context_t *restrict scontext, const char *restrict domain,
                                                   uint8_t len)
{
    if (scontext->domain != NULL && ! scontext->domain_constant)
    {
        memoryFree(scontext->domain); // Free previous allocation
    }
    scontext->domain          = (char *) domain; // Use constant memory pointer
    scontext->domain_len      = len;
    scontext->domain_constant = true;
    assert(scontext->domain[len] == '\0'); // Ensure null-termination
    scontext->type_ip = kCCTypeDomain;
}

/**
 * @brief Copy an address context.
 *
 * Copies flags, port, and either IP address or domain.
 */
static inline void addresscontextAddrCopy(connection_context_t *dest, const connection_context_t *const source)
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

// ============================================================================
// Protocol Flag Management Functions
// ============================================================================
/**
 * @brief Enable/Disable protocol flags.
 */
static inline void addressContextEnableTcp(connection_context_t *dest)
{
    dest->proto_tcp = true;
}
static inline void addressContextDisableTcp(connection_context_t *dest)
{
    dest->proto_tcp = false;
}
static inline void addressContextEnableUdp(connection_context_t *dest)
{
    dest->proto_ucp = true;
}
static inline void addressContextDisableUdp(connection_context_t *dest)
{
    dest->proto_ucp = false;
}
static inline void addressContextEnableIcmp(connection_context_t *dest)
{
    dest->proto_icmp = true;
}
static inline void addressContextDisableIcmp(connection_context_t *dest)
{
    dest->proto_icmp = false;
}
static inline void addressContextEnablePacket(connection_context_t *dest)
{
    dest->proto_packet = true;
}
static inline void addressContextDisablePacket(connection_context_t *dest)
{
    dest->proto_packet = false;
}

/**
 * @brief Set protocol flag based on socket address protocol enum.
 */
static inline void addresscontextSetProtocol(connection_context_t *dest, enum socket_address_protocol protocol)
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

// ============================================================================
// IP Address Management Functions
// ============================================================================
/**
 * @brief Set the IP address for an address context.
 */
static void addresscontextSetIp(connection_context_t *restrict scontext, const ip_addr_t *restrict ip)
{
    scontext->ip_address = *ip;
    scontext->type_ip    = kCCTypeIp;
}

/**
 * @brief Set the IP address and port for an address context.
 */
static void addresscontextSetIpPort(connection_context_t *restrict scontext, const ip_addr_t *restrict ip,
                                    uint16_t port)
{
    scontext->ip_address = *ip;
    scontext->port       = port;
    scontext->type_ip    = kCCTypeIp;
}

/**
 * @brief Clear the IP address in an address context.
 *
 * Sets IP to any (zero) and marks it as non-IP.
 */
static inline void addressContextClearIp(connection_context_t *ctx)
{
    ipAddrSetAny(false, &ctx->ip_address); // false indicates IPv4 wildcard
    ctx->type_ip = kCCTypeDomain;
}

/**
 * @brief Detect IP version from a host string.
 *
 * @param host Pointer to host string.
 * @return IP type value (IPADDR_TYPE_V4 or IPADDR_TYPE_V6), or 0 if invalid.
 */
static inline uint8_t getIpVersion(char *host)
{
    if (isIPVer4(host))
    {
        return IPADDR_TYPE_V4;
    }
    if (isIPVer6(host))
    {
        return IPADDR_TYPE_V6;
    }
    return 0; // Not a valid IP
}

// ============================================================================
// Address Conversion Functions
// ============================================================================

static inline  connectioncontextFromSockAddr(connection_context_t *dest,const sockaddr_u *src)
{
    
    addressContextInit(dest);
    sockaddrToIpAddr(src, &dest->ip_address);

    if (src->sa.sa_family == AF_INET)
    {
        dest->port = ntohs(src->sin.sin_port);
    }
    else if (src->sa.sa_family == AF_INET6)
    {
        dest->port = ntohs(src->sin6.sin6_port);
    }
    dest->type_ip = kCCTypeIp;
}

/**
 * @brief Convert an address context with IP to a sockaddr structure.
 */
static inline sockaddr_u connectioncontextToSockAddr(const connection_context_t *context)
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
    if (context->ip_address.type == IPADDR_TYPE_V6)
    {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *) &addr;
        addr_in6->sin6_family         = AF_INET6;
        addr_in6->sin6_port           = htons(context->port);
        memoryCopy(&addr_in6->sin6_addr.s6_addr, &context->ip_address.u_addr.ip6, sizeof(addr_in6->sin6_addr.s6_addr));
        return addr;
    }
    assert(false); // Not a valid IP type
    return (sockaddr_u){0};
}
