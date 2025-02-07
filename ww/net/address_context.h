#pragma once

#include "wlibc.h"
#include "wsocket.h"

enum domain_strategy
{
    kDsInvalid,
    kDsPreferIpV4,
    kDsPreferIpV6,
    kDsOnlyIpV4,
    kDsOnlyIpV6
};

enum socket_address_protocol
{
    kSapTcp = IPPROTO_TCP,
    kSapUdp = IPPROTO_UDP,
};

typedef struct ip_address_s
{
    /* NETWORK BYTE ORDER */
    union {
        uint32_t addr;         /* IPv4 address (32 bits) */
        uint16_t addr_ipv6[8]; /* IPv6 address (128 bits, represented as 8 x 16-bit words) */
    } u_addr;
    uint16_t type; /* Type of the address: IPv4 or IPv6 (AF_INET OR AF_INET6)*/
} ip_address_t;

typedef struct address_context_s
{
    // i think we could define them as union but its better not to (IMO)
    ip_address_t         ip_address; // network byte order
    uint16_t             port;       // host byte order
    char                *domain;
    enum domain_strategy domain_strategy;
    uint8_t              domain_len;

    uint8_t domain_constant : 1; // domain points to constant memory , should not be freed
    uint8_t type_ip : 1;         // ip or domain? when domain is resolved then it becomes ip
    uint8_t proto_tcp : 1;
    uint8_t proto_ucp : 1;
    uint8_t proto_icmp : 1;
    uint8_t proto_packet : 1;

} address_context_t;

static inline void addresscontextPortCopy(address_context_t *dest, address_context_t *source)
{
    dest->port = source->port;
}

static inline void addresscontextPortSet(address_context_t *dest, uint16_t port)
{
    dest->port = port;
}

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

// Helper function to copy sockaddr_in or sockaddr_in6 to ip_address_t
static inline void sockaddrToIpAddressCopy(const sockaddr_u *src, ip_address_t *dest)
{
    assert(src != NULL && dest != NULL);

    if (((const struct sockaddr *) src)->sa_family == AF_INET)
    {
        // Copy IPv4 address
        const struct sockaddr_in *src_in = (const struct sockaddr_in *) src;
        dest->u_addr.addr                = src_in->sin_addr.s_addr;
        dest->type                       = AF_INET;
    }
    else if (((const struct sockaddr *) src)->sa_family == AF_INET6)
    {
        // Copy IPv6 address
        const struct sockaddr_in6 *src_in6 = (const struct sockaddr_in6 *) src;
        memcpy(dest->u_addr.addr_ipv6, &src_in6->sin6_addr.s6_addr, sizeof(dest->u_addr.addr_ipv6));
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
        addr_in->sin_addr.s_addr    = context->ip_address.u_addr.addr;
        return addr;
    }
    if (context->ip_address.type == AF_INET6)
    {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *) &addr;
        addr_in6->sin6_family         = AF_INET6;
        addr_in6->sin6_port           = htons(context->port);
        memcpy(&addr_in6->sin6_addr.s6_addr, context->ip_address.u_addr.addr_ipv6, sizeof(addr_in6->sin6_addr.s6_addr));

        return addr;
    }
    assert(false); // not valid ip type
    return (sockaddr_u) {0};

}

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
