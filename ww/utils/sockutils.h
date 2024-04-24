#pragma once
#include "basic_types.h"
#include "hsocket.h"

void sockAddrCopy(sockaddr_u *restrict dest, const sockaddr_u *restrict source);
bool sockAddrCmpIPV4(const sockaddr_u *restrict addr1, const sockaddr_u *restrict addr2);
bool sockAddrCmpIPV6(const sockaddr_u *restrict addr1, const sockaddr_u *restrict addr2);
bool sockAddrCmpIP(const sockaddr_u *restrict addr1, const sockaddr_u *restrict addr2);

void socketContextAddrCopy(socket_context_t *dest, const socket_context_t *source);
void socketContextPortCopy(socket_context_t *dest, socket_context_t *source);
void socketContextPortSet(socket_context_t *dest, uint16_t port);
void socketContextDomainSet(socket_context_t *restrict scontext, const char *restrict domain, uint8_t len);
void socketContextDomainSetConstMem(socket_context_t *restrict scontext, const char *restrict domain, uint8_t len);

enum socket_address_type getHostAddrType(char *host);
