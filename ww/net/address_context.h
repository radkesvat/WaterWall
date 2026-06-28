#pragma once

/*
 * Unified address context utilities for IP/domain endpoints and protocol flags.
 */

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

enum
{
    kAddressContextProtocolHttp1      = 1U << 0U,
    kAddressContextProtocolTls        = 1U << 1U,
    kAddressContextProtocolBittorrent = 1U << 2U,
};

/*
 * Optional routing metadata. These flags are not intrinsic endpoint identity;
 * Router sets them opportunistically from the first payload window.
 */
typedef struct address_context_optional_flags_s
{
    uint32_t detected_protocols;
} address_context_optional_flags_t;

/**
 * Connction context provieds complete information about a connection. It can be used to connecto to somewhere.
 * in a line, there is 2 of this struct, one for source and one for destination.
 */
typedef struct address_context_s
{
    ip_addr_t                        ip_address;      // IP address in network byte order
    uint16_t                         port;            // Port number in host byte order
    char                            *domain;          // Domain name if applicable
    enum domain_strategy             domain_strategy; // DNS resolution strategy
    uint8_t                          domain_len;      // Length of domain name
    address_context_optional_flags_t optional_flags;  // Router-owned optional metadata

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
 * @brief Clear optional routing metadata.
 */
static inline void addresscontextClearOptionalFlags(address_context_t *ctx)
{
    ctx->optional_flags = (address_context_optional_flags_t) {0};
}

/**
 * @brief Clear all transport protocol flags on an address context.
 */
static inline void addresscontextClearProtocols(address_context_t *ctx)
{
    ctx->proto_tcp    = false;
    ctx->proto_udp    = false;
    ctx->proto_icmp   = false;
    ctx->proto_packet = false;
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

/**
 * @brief Replace protocol flags with a single protocol selection.
 */
static inline void addresscontextSetOnlyProtocol(address_context_t *dest, uint8_t protocol)
{
    addresscontextClearProtocols(dest);
    addresscontextSetProtocol(dest, protocol);
}

// ============================================================================
// IP Address Management Functions
// ============================================================================
/**
 * @brief Set the IP address for an address context.
 */
static inline void addresscontextSetIp(address_context_t *ctx, const ip_addr_t *ip)
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
static inline bool addresscontextSetIpAddress(address_context_t *ctx, const char *ip_str)
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
static inline void addresscontextSetIpPort(address_context_t *ctx, const ip_addr_t *ip, uint16_t port)
{
    addresscontextReset(ctx);
    ctx->ip_address = *ip;
    ctx->port       = port;
    ctx->type_ip    = kCCTypeIp;
}

/**
 * @brief Set the IP address, port, and protocol for an address context.
 */
static inline void addresscontextSetIpPortProtocol(address_context_t *ctx, const ip_addr_t *ip, uint16_t port,
                                                   uint8_t protocol)
{
    addresscontextSetIpPort(ctx, ip, port);
    addresscontextSetOnlyProtocol(ctx, protocol);
}

/**
 * @brief Set the IP address and port from a string.
 *
 * Parses the string and sets the IP address and port in the context.
 * Returns true if successful, false if invalid.
 */
static inline bool addresscontextSetIpAddressPort(address_context_t *ctx, const char *ip_str, uint16_t port)
{
    addresscontextReset(ctx);

    if (ipaddr_aton(ip_str, &ctx->ip_address))
    {
        ctx->type_ip = kCCTypeIp;
        ctx->port    = port;
        return true; // Successfully parsed IP address
    }
    return false; // Invalid IP string
}

/**
 * @brief Set the IP address, port, and protocol from a string.
 */
static inline bool addresscontextSetIpAddressPortProtocol(address_context_t *ctx, const char *ip_str, uint16_t port,
                                                          uint8_t protocol)
{
    if (! addresscontextSetIpAddressPort(ctx, ip_str, port))
    {
        return false;
    }

    addresscontextSetOnlyProtocol(ctx, protocol);
    return true;
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
 * @brief Set the domain resolution strategy for an address context.
 */
static inline void addresscontextSetDomainStrategy(address_context_t *ctx, enum domain_strategy strategy)
{
    ctx->domain_strategy = strategy;
}

/**
 * @brief Check whether the address context has a non-zero port.
 */
static inline bool addresscontextHasPort(const address_context_t *ctx)
{
    return ctx->port != 0;
}

/**
 * @brief Clear the IP address in an address context.
 *
 * Sets IP to any (zero) and marks it as non-IP.
 */
static inline void addresscontextClearIp(address_context_t *ctx)
{
    ipAddrSetAny(false, &ctx->ip_address); // false indicates IPv4 wildcard
    ctx->type_ip         = kCCTypeDomain;
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
    assert(len <= UINT8_MAX);

    ctx->domain = memoryAllocate((size_t) len + 1U);
    memoryCopy(ctx->domain, domain, len);
    ctx->domain[len]     = '\0';
    ctx->domain_len      = len;
    ctx->domain_constant = false;
    ctx->domain_resolved = false;
    ctx->type_ip         = kCCTypeDomain;
}

/**
 * @brief Set a domain from a null-terminated C string (dynamic memory).
 */
static inline void addresscontextDomainSetByString(address_context_t *ctx, const char *domain)
{
    size_t len = stringLength(domain);
    assert(len <= UINT8_MAX);
    addresscontextDomainSet(ctx, domain, (uint8_t) len);
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
 * Use this when the caller needs a concrete endpoint address. This excludes
 * wildcard/any addresses such as 0.0.0.0 and ::.
 */
static inline bool addresscontextIsIp(const address_context_t *context)
{
    return context->type_ip == kCCTypeIp && ! ipAddrIsAny(&context->ip_address);
}

/**
 * @brief Check if the context is IP-typed, even if the IP is an any/wildcard address.
 *
 * This is a shape/type check, not a resolved-endpoint check. It returns true
 * for wildcard/any addresses such as 0.0.0.0 and ::. Use addresscontextIsIp()
 * instead when marking a domain as resolved or when a real destination IP is
 * required.
 */
static inline bool addresscontextIsIpType(const address_context_t *context)
{
    return context->type_ip == kCCTypeIp;
}

/**
 * @brief Store an observed domain name without replacing the address endpoint.
 *
 * Sniffed metadata such as HTTP Host or TLS SNI should not clear an already
 * known destination IP/port/protocol. For concrete IP-backed contexts, mark the
 * domain as resolved so downstream connectors keep using the preserved IP
 * address. For domain-only or wildcard-IP contexts, leave it unresolved because
 * there is no concrete IP address represented by the observed domain.
 */
static inline bool addresscontextSetObservedDomain(address_context_t *ctx, const uint8_t *domain, uint32_t len)
{
    if (domain == NULL || len == 0 || len > UINT8_MAX)
    {
        return false;
    }

    char *copy = memoryAllocate((size_t) len + 1U);
    memoryCopy(copy, domain, len);
    copy[len] = '\0';

    if (ctx->domain != NULL && ! ctx->domain_constant)
    {
        memoryFree(ctx->domain);
    }

    ctx->domain          = copy;
    ctx->domain_len      = (uint8_t) len;
    ctx->domain_constant = false;
    ctx->domain_resolved = addresscontextIsIp(ctx);

    return true;
}

/**
 * @brief Check if the context carries an any/wildcard IP.
 */
static inline bool addresscontextIsAnyIp(const address_context_t *context)
{
    return addresscontextIsIpType(context) && ipAddrIsAny(&context->ip_address);
}

/**
 * @brief Check if the context currently uses IPv4.
 */
static inline bool addresscontextIsIpv4(const address_context_t *context)
{
    return addresscontextIsIpType(context) && context->ip_address.type == IPADDR_TYPE_V4;
}

/**
 * @brief Check if the context currently uses IPv6.
 */
static inline bool addresscontextIsIpv6(const address_context_t *context)
{
    return addresscontextIsIpType(context) && context->ip_address.type == IPADDR_TYPE_V6;
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

/**
 * @brief Check whether a domain context has already been resolved to IP.
 *
 * @param context Address context to inspect.
 * @return true Domain has a resolved IP.
 * @return false Domain is not resolved yet.
 */
static inline bool addresscontextIsDomainResolved(const address_context_t *context)
{
    return context->domain_resolved;
}

/**
 * @brief Check whether the context can be converted to a sockaddr right now.
 */
static inline bool addresscontextCanConvertToSockAddr(const address_context_t *context)
{
    return addresscontextIsIpType(context) || (addresscontextIsDomain(context) && context->domain_resolved);
}

/**
 * @brief Get socket address family for the current resolved/IP address.
 */
static inline int addresscontextGetSockAddrFamily(const address_context_t *context)
{
    if (! addresscontextCanConvertToSockAddr(context))
    {
        return AF_UNSPEC;
    }

    switch (context->ip_address.type)
    {
    case IPADDR_TYPE_V4:
        return AF_INET;
    case IPADDR_TYPE_V6:
        return AF_INET6;
    default:
        return AF_UNSPEC;
    }
}

/**
 * @brief Get a socket type hint from the current transport protocol flags.
 *
 * Returns 0 when the context has no single TCP or UDP protocol selection.
 */
static inline int addresscontextGetSockType(const address_context_t *context)
{
    if (context->proto_tcp && ! context->proto_udp)
    {
        return SOCK_STREAM;
    }
    if (context->proto_udp && ! context->proto_tcp)
    {
        return SOCK_DGRAM;
    }

    return 0;
}

/**
 * @brief Copy an address context.
 *
 * Copies flags, port, and either IP address or domain.
 */
static inline void addresscontextAddrCopy(address_context_t *dest, const address_context_t *const source)
{
    addresscontextReset(dest);

    // Copy IP address or domain
    if (source->type_ip)
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

    // Copy metadata after domain helpers, because they reset the destination.
    dest->domain_strategy = source->domain_strategy;
    dest->domain_constant = source->domain_constant;
    dest->type_ip         = source->type_ip;
    dest->proto_tcp       = source->proto_tcp;
    dest->proto_udp       = source->proto_udp;
    dest->proto_icmp      = source->proto_icmp;
    dest->proto_packet    = source->proto_packet;
    dest->domain_resolved = source->domain_resolved;
    dest->port            = source->port;
    dest->optional_flags  = source->optional_flags;
}

// ============================================================================
// Address Conversion Functions
// ============================================================================

/**
 * @brief Populate an address context from a sockaddr container.
 *
 * @param dest Destination context.
 * @param src Source socket address.
 */
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
 * @brief Populate an address context from a sockaddr and set a single protocol.
 */
static inline void addresscontextFromSockAddrWithProtocol(address_context_t *dest, const sockaddr_u *src,
                                                          uint8_t protocol)
{
    addresscontextFromSockAddr(dest, src);
    addresscontextSetOnlyProtocol(dest, protocol);
}

/**
 * @brief Convert an address context with IP to a sockaddr structure.
 */
static inline sockaddr_u addresscontextToSockAddr(const address_context_t *context)
{
    // Zero the whole union first: each branch below only fills a subset of the sockaddr fields
    // (IPv4 leaves sin_zero; IPv6 leaves sin6_flowinfo and sin6_scope_id). Those bytes are read
    // verbatim by connect()/sendto(), so leaving them uninitialized feeds garbage to the kernel.
    sockaddr_u addr = {0};
    assert(addresscontextCanConvertToSockAddr(context));
    if (addresscontextIsIpv4(context))
    {
        struct sockaddr_in *addr_in = (struct sockaddr_in *) &addr;
        addr_in->sin_family         = AF_INET;
        addr_in->sin_port           = htons(context->port);
        addr_in->sin_addr.s_addr    = context->ip_address.u_addr.ip4.addr;
        return addr;
    }
    if (addresscontextIsIpv6(context))
    {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *) &addr;
        addr_in6->sin6_family         = AF_INET6;
        addr_in6->sin6_port           = htons(context->port);
        memoryCopy(&addr_in6->sin6_addr.s6_addr, &context->ip_address.u_addr.ip6, sizeof(addr_in6->sin6_addr.s6_addr));
        return addr;
    }
    assert(false); // Not a valid IP type
    return (sockaddr_u) {0};
}
