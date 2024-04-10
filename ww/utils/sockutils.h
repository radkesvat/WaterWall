#pragma once
#include "hv/hsocket.h"
#include "basic_types.h"

#define CMP(a, b) \
    if (a != b)   \
    return false
inline bool socket_cmp_ipv4(sockaddr_u *restrict addr1, sockaddr_u *restrict addr2)
{

    return (addr1->sin.sin_addr.s_addr == addr2->sin.sin_addr.s_addr);
}

inline bool socket_cmp_ipv6(sockaddr_u *restrict addr1, sockaddr_u *restrict addr2)
{
    int r = memcmp(addr1->sin6.sin6_addr.s6_addr, addr2->sin6.sin6_addr.s6_addr, sizeof(addr1->sin6.sin6_addr.s6_addr));
    if (r != 0)
        return r;
    CMP(addr1->sin6.sin6_flowinfo, addr2->sin6.sin6_flowinfo);
    CMP(addr1->sin6.sin6_scope_id, addr2->sin6.sin6_scope_id);
    return false;
}

#undef CMP

bool socket_cmp_ip(sockaddr_u *restrict addr1, sockaddr_u *restrict addr2);

void copySocketContextAddr(socket_context_t *dest, socket_context_t **source);
void copySocketContextPort(socket_context_t *dest, socket_context_t *source);
enum socket_address_type getHostAddrType(char *host);
