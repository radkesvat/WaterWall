#pragma once
#include "basic_types.h"
#include "hsocket.h"
#include "tunnel.h"
#include <stdint.h>

void   sockAddrCopy(sockaddr_u *restrict dest, const sockaddr_u *restrict source);
bool   sockAddrCmpIPV4(const sockaddr_u *restrict addr1, const sockaddr_u *restrict addr2);
bool   sockAddrCmpIPV6(const sockaddr_u *restrict addr1, const sockaddr_u *restrict addr2);
bool   sockAddrCmpIP(const sockaddr_u *restrict addr1, const sockaddr_u *restrict addr2);
hash_t sockAddrCalcHashNoPort(const sockaddr_u *saddr);
hash_t sockAddrCalcHashWithPort(const sockaddr_u *saddr);

void socketContextAddrCopy(socket_context_t *dest, const socket_context_t *source);
void socketContextPortCopy(socket_context_t *dest, socket_context_t *source);
void socketContextPortSet(socket_context_t *dest, uint16_t port);
void socketContextDomainSet(socket_context_t *restrict scontext, const char *restrict domain, uint8_t len);
void socketContextDomainSetConstMem(socket_context_t *restrict scontext, const char *restrict domain, uint8_t len);

struct logger_s;
bool                     verifyIpCdir(const char *ipc, struct logger_s *logger);
enum socket_address_type getHostAddrType(char *host);

int parseIPWithSubnetMask(struct in6_addr *base_addr, const char *input, struct in6_addr *subnet_mask);

static inline int checkIPRange4(const struct in_addr test_addr, const struct in_addr base_addr,
                                const struct in_addr subnet_mask)
{
    if ((test_addr.s_addr & subnet_mask.s_addr) == (base_addr.s_addr & subnet_mask.s_addr))
    {
        return 1;
    }
    return 0;
}

static inline int checkIPRange6(const struct in6_addr test_addr, const struct in6_addr base_addr,
                                const struct in6_addr subnet_mask)
{

    // uint64_t *test_addr_p   = (uint64_t *) &(test_addr.s6_addr[0]);
    // uint64_t *base_addr_p   = (uint64_t *) &(base_addr.s6_addr[0]);
    // uint64_t *subnet_mask_p = (uint64_t *) &(subnet_mask.s6_addr[0]);

    // if ((base_addr_p[0] & subnet_mask_p[0]) != test_addr_p[0] || (base_addr_p[1] & subnet_mask_p[1]) !=
    // test_addr_p[1])
    // {
    //     return 0;
    // }
    // return 1;

    struct in6_addr masked_test_addr;
    struct in6_addr masked_base_addr;

    for (int i = 0; i < 16; i++)
    {
        masked_test_addr.s6_addr[i] = test_addr.s6_addr[i] & subnet_mask.s6_addr[i];
        masked_base_addr.s6_addr[i] = base_addr.s6_addr[i] & subnet_mask.s6_addr[i];
    }

    if (memcmp(&masked_test_addr, &masked_base_addr, sizeof(struct in6_addr)) == 0)
    {
        return 1;
    }
    return 0;
}
