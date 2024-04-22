#pragma once
#include "basic_types.h"
#include "hv/hsocket.h"

inline void sockAddrCopy(sockaddr_u *restrict dest, const sockaddr_u *restrict source)
{
    if (source->sa.sa_family == AF_INET)
    {
        memcpy(&(dest->sin.sin_addr.s_addr), &(source->sin.sin_addr.s_addr), sizeof(source->sin.sin_addr.s_addr));
        return;
    }
    memcpy(&(dest->sin6.sin6_addr.s6_addr), &(source->sin6.sin6_addr.s6_addr), sizeof(source->sin6.sin6_addr.s6_addr));
}

inline bool sockAddrCmpIPV4(const sockaddr_u *restrict addr1, const sockaddr_u *restrict addr2)
{
    return (addr1->sin.sin_addr.s_addr == addr2->sin.sin_addr.s_addr);
}

inline bool sockAddrCmpIPV6(const sockaddr_u *restrict addr1, const sockaddr_u *restrict addr2)
{
    int r = memcmp(addr1->sin6.sin6_addr.s6_addr, addr2->sin6.sin6_addr.s6_addr, sizeof(addr1->sin6.sin6_addr.s6_addr));
    if (r != 0)
    {
        return false;
    }
    if (addr1->sin6.sin6_flowinfo != addr2->sin6.sin6_flowinfo)
    {
        return false;
    }
    if (addr1->sin6.sin6_scope_id, addr2->sin6.sin6_scope_id)
    {
        return false;
    }
    return true;
}

bool        socketCmpIP(const sockaddr_u *restrict addr1, const sockaddr_u *restrict addr2);
void        copySocketContextAddr(socket_context_t *dest, const socket_context_t *source);
void        copySocketContextPort(socket_context_t *dest, socket_context_t *source);
inline void setSocketContextPort(socket_context_t *dest, uint16_t port)
{
    dest->addr.sin.sin_port = port;
}

enum socket_address_type getHostAddrType(char *host);

inline void allocateDomainBuffer(socket_context_t *scontext)
{
    if (scontext->domain == NULL)
    {
        scontext->domain = malloc(256);
#ifdef DEBUG
        memset(scontext->domain, 0xEE, 256);
#endif
    }
}
// len is max 255 since it is 8bit
inline void setSocketContextDomain(socket_context_t *restrict scontext,const char *restrict domain, uint8_t len)
{
    assert(scontext->domain != NULL);
    memcpy(scontext->domain, domain, len);
    scontext->domain[len] = 0x0;
    scontext->domain_len = len;
}