#pragma once
#include "wlibc.h"

#include "lwip/ip.h"
#include "lwip/ip_addr.h"

typedef struct ip_hdr ip_hdr_t;

#define ip6AddrSetAny     ip6_addr_set_any
#define ip4AddrSetAny     ip4_addr_set_any
#define ipAddrSetAny      ip_addr_set_any
#define ipAddrIsAny       ip_addr_isany
#define ipAddrCmp         ip_addr_cmp
#define ipAddrNetcmp      ip_addr_netcmp
#define ip4AddrGetU32     ip4_addr_get_u32
#define ipAddrCopyFromIp4 ip_addr_copy_from_ip4
#define ipAddrNetcmp      ip_addr_netcmp
#define ip4AddrNetcmp     ip4_addr_netcmp
#define ip6AddrNetcmp     ip6_addr_netcmp
