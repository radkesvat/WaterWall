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

#define IP_PROTO_PACKET 255

/**
 * Connction context provieds complete information about a connection. It can be used to connecto to somewhere.
 * in a line, there is 2 of this struct, one for source and one for destination.
 */
typedef struct address_context_s
{
    ip_addr_t            ip_address;      // IP address in network byte order
    uint16_t             port;            // Port number in host byte order
    char                *domain;          // Domain name if applicable
    enum domain_strategy domain_strategy; // DNS resolution strategy
    uint8_t              domain_len;      // Length of domain name

    // Flags for address properties
    uint8_t type_ip : 1;         // True for IP address, false for domain
    uint8_t proto_tcp : 1;       // TCP protocol enabled
    uint8_t proto_udp : 1;       // UDP protocol enabled
    uint8_t proto_icmp : 1;      // ICMP protocol enabled
    uint8_t proto_packet : 1;    // Raw packet protocol enabled
    uint8_t domain_constant : 1; // True if domain points to constant memory, will not free it
    uint8_t domain_resolved : 1; // True if domain has been resolved and we have its address

} address_context_t;

// ============================================================================
// Initialization and Reset Helpers
// ============================================================================


/**
 * @brief Reset an address context structure.
 *
 * Frees domain memory if allocated (non-constant) and resets all fields.
 */
static inline void addresscontextReset(address_context_t *ctx)
{
    if (ctx->domain != NULL && ! ctx->domain_constant)
    {
        memoryFree(ctx->domain);
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->type_ip = kCCTypeDomain;
}

/**
 * @brief Set protocol flag based on socket address protocol enum.
 * see lwip/prot/iana.h
 */
static inline void addresscontextSetProtocol(address_context_t *dest, uint8_t protocol)
{
    switch (protocol)
    {
    case IP_PROTO_TCP:
        dest->proto_tcp = true;
        break;
    case IP_PROTO_UDP:
        dest->proto_udp = true;
        break;
    case IP_PROTO_ICMP:
        dest->proto_icmp = true;
        break;
    case IP_PROTO_PACKET: // Raw packet protocol (custom flag)
        dest->proto_packet = true;
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
static void addresscontextSetIp(address_context_t *ctx, const ip_addr_t *ip)
{
    addresscontextReset(ctx);
    ctx->ip_address = *ip;
    ctx->type_ip    = kCCTypeIp;
}

/**
 * @brief Set the IP address from a string.
 *
 * Parses the string and sets the IP address in the context.
 * Returns true if successful, false if invalid.
 */
static bool addresscontextSetIpAddress(address_context_t *ctx, const char *ip_str)
{
    addresscontextReset(ctx);

    if (ipaddr_aton(ip_str, &ctx->ip_address))
    {
        ctx->type_ip = kCCTypeIp;
        return true; // Successfully parsed IP address
    }
    return false; // Invalid IP string
}

/**
 * @brief Set the IP address and port for an address context.
 */
static void addresscontextSetIpPort(address_context_t *ctx, const ip_addr_t *ip, uint16_t port)
{
    addresscontextReset(ctx);
    ctx->ip_address = *ip;
    ctx->port       = port;
    ctx->type_ip    = kCCTypeIp;
}

/**
 * @brief Set the IP address and port from a string.
 *
 * Parses the string and sets the IP address and port in the context.
 * Returns true if successful, false if invalid.
 */
static bool addresscontextSetIpAddressPort(address_context_t *ctx, const char *ip_str, uint16_t port)
{
    if (ipaddr_aton(ip_str, &ctx->ip_address))
    {
        ctx->type_ip = kCCTypeIp;
        ctx->port    = port;
        return true; // Successfully parsed IP address
    }
    return false; // Invalid IP string
}

/**
 * @brief Copy port from source to destination context.
 */
static inline void addresscontextCopyPort(address_context_t *dest, address_context_t *source)
{
    dest->port = source->port;
}

/**
 * @brief Set the port for an address context.
 */
static inline void addresscontextSetPort(address_context_t *dest, uint16_t port)
{
    dest->port = port;
}

/**
 * @brief Clear the IP address in an address context.
 *
 * Sets IP to any (zero) and marks it as non-IP.
 */
static inline void addresscontextClearIp(address_context_t *ctx)
{
    ipAddrSetAny(false, &ctx->ip_address); // false indicates IPv4 wildcard
    ctx->type_ip = kCCTypeDomain;
    ctx->domain_resolved = false;
}

// ============================================================================
// Domain Name Management Functions
// ============================================================================
/**
 * @brief Set a domain for the address context (dynamic memory).
 */
static inline void addresscontextDomainSet(address_context_t *ctx, const char *domain, uint8_t len)
{
    addresscontextReset(ctx);

    ctx->domain = memoryAllocate(256);
    memoryCopy(ctx->domain, domain, len);
    ctx->domain[len]     = '\0';
    ctx->domain_len      = len;
    ctx->domain_constant = false;
    ctx->domain_resolved = false;
    ctx->type_ip         = kCCTypeDomain;
}

/**
 * @brief Set a domain for the address context using constant memory.
 */
static inline void addresscontextDomainSetConstMem(address_context_t *ctx, const char *domain, uint8_t len)
{
    addresscontextReset(ctx);

    ctx->domain          = (char *) domain; // Use constant memory pointer
    ctx->domain_len      = len;
    ctx->domain_constant = true;
    ctx->domain_resolved = false;
    assert(ctx->domain[len] == '\0'); // Ensure null-termination
    ctx->type_ip = kCCTypeDomain;
}



// ============================================================================
// Validation Helper
// ============================================================================

/**
 * @brief Check if the address context is a valid IP.
 *
 * Validates that the context is of type IP and has a non-empty address.
 */
static inline bool addresscontextIsIp(const address_context_t *context)
{
    return context->type_ip == kCCTypeIp && ! ipAddrIsAny(&context->ip_address);
}

/**
 * @brief Check if the address context is a valid domain.
 *
 * Validates that the context is of type domain and has a non-empty domain name.
 */
static inline bool addresscontextIsDomain(const address_context_t *context)
{
    return context->type_ip == kCCTypeDomain && context->domain != NULL && context->domain_len > 0;
}

/**
 * @brief Check whether the address context contains a valid IP or domain.
 *
 * @param context The address context to verify.
 * @return true if valid; false otherwise.
 */
static inline bool addresscontextIsValid(const address_context_t *context)
{

    return addresscontextIsIp(context) || addresscontextIsDomain(context);
}

static inline bool addresscontextIsDomainResolved(const address_context_t *context)
{
    return context->domain_resolved;
}

/**
 * @brief Copy an address context.
 *
 * Copies flags, port, and either IP address or domain.
 */
static inline void addresscontextAddrCopy(address_context_t *dest, const address_context_t *const source)
{
    addresscontextReset(dest);

    // Copy flags
    dest->domain_constant = source->domain_constant;
    dest->type_ip         = source->type_ip;
    dest->proto_tcp       = source->proto_tcp;
    dest->proto_udp       = source->proto_udp;
    dest->proto_icmp      = source->proto_icmp;
    dest->proto_packet    = source->proto_packet;
    dest->domain_resolved = source->domain_resolved;
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
                addresscontextDomainSetConstMem(dest, source->domain, source->domain_len);
            }
            else
            {
                addresscontextDomainSet(dest, source->domain, source->domain_len);
            }

            if (source->domain_resolved)
            {
                ipAddrCopy(dest->ip_address, source->ip_address);
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
// Address Conversion Functions
// ============================================================================

static inline void addresscontextFromSockAddr(address_context_t *dest, const sockaddr_u *src)
{

    addresscontextReset(dest);
    sockaddrToIpAddr(src, &dest->ip_address);

    if (src->sa.sa_family == AF_INET)
    {
        dest->port    = ntohs(src->sin.sin_port);
        dest->type_ip = kCCTypeIp;
    }
    else if (src->sa.sa_family == AF_INET6)
    {
        dest->port    = ntohs(src->sin6.sin6_port);
        dest->type_ip = kCCTypeIp;
    }
}

/**
 * @brief Convert an address context with IP to a sockaddr structure.
 */
static inline sockaddr_u addresscontextToSockAddr(const address_context_t *context)
{
    sockaddr_u addr;
    assert(context->type_ip || context->domain_resolved);
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
