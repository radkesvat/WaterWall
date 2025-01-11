#pragma once
#include "basic_types.h"
#include "wsocket.h"
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
bool                     verifyIPCdir(const char *ipc, struct logger_s *logger);
enum socket_address_type getHostAddrType(char *host);

int parseIPWithSubnetMask(struct in6_addr *base_addr, const char *input, struct in6_addr *subnet_mask);
