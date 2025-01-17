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

enum dynamic_value_status
{
    kDvsEmpty = 0x0,
    kDvsConstant,
    kDvsFirstOption,
};


enum socket_address_type
{
    kSatIPV4       = 0X1,
    kSatDomainName = 0X3,
    kSatIPV6       = 0X4,
};

enum socket_address_protocol
{
    kSapTcp = IPPROTO_TCP,
    kSapUdp = IPPROTO_UDP,
};

typedef struct socket_context_s
{
    char                        *domain;
    sockaddr_u                   address;
    enum socket_address_protocol address_protocol;
    enum socket_address_type     address_type;
    enum domain_strategy         domain_strategy;
    unsigned int                 domain_len;
    bool                         domain_resolved;
    bool                         domain_constant;

} socket_context_t;

static inline void socketContextAddrCopy(socket_context_t *dest, const socket_context_t *const source)
{
    dest->address_protocol = source->address_protocol;
    dest->address_type     = source->address_type;
    switch (dest->address_type)
    {
    case kSatIPV4:
        dest->address.sa.sa_family = AF_INET;
        dest->address.sin.sin_addr = source->address.sin.sin_addr;

        break;

    case kSatDomainName:
        dest->address.sa.sa_family = AF_INET;
        if (source->domain != NULL)
        {
            if (source->domain_constant)
            {
                socketContextDomainSetConstMem(dest, source->domain, source->domain_len);
            }
            else
            {
                socketContextDomainSet(dest, source->domain, source->domain_len);
            }
            dest->domain_resolved = source->domain_resolved;
            if (source->domain_resolved)
            {
                dest->domain_resolved = true;
                sockaddrCopy(&(dest->address), &(source->address));
            }
        }

        break;

    case kSatIPV6:
        dest->address.sa.sa_family = AF_INET6;
        memoryCopy(&(dest->address.sin6.sin6_addr), &(source->address.sin6.sin6_addr), sizeof(struct in6_addr));

        break;
    }
}

static inline void socketContextPortCopy(socket_context_t *dest, socket_context_t *source)
{
    // this is supposed to work for both ipv4/6
    dest->address.sin.sin_port = source->address.sin.sin_port;

    // alternative:

    // switch (dest->address_type)
    // {
    // case kSatIPV4:
    // case kSatDomainName:
    // default:
    //     dest->address.sin.sin_port = source->address.sin.sin_port;
    //     break;

    // case kSatIPV6:
    //     dest->address.sin6.sin6_port = source->address.sin6.sin6_port;
    //     break;
    // }
}

static inline void socketContextPortSet(socket_context_t *dest, uint16_t port)
{
    dest->address.sin.sin_port = htons(port);
}

static inline void socketContextDomainSet(socket_context_t *restrict scontext, const char *restrict domain, uint8_t len)
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

static inline void socketContextDomainSetConstMem(socket_context_t *restrict scontext, const char *restrict domain, uint8_t len)
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



static inline enum socket_address_type getHostAddrType(char *host)
{
    if (isIPVer4(host))
    {
        return kSatIPV4;
    }
    if (isIPVer6(host))
    {
        return kSatIPV6;
    }
    return kSatDomainName;
}
