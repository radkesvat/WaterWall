#pragma once
#include "wlibc.h"

#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/ip4_frag.h"
#include "lwip/ip_addr.h"
#include "lwip/pbuf.h"
#include "lwip/tcpip.h"
#include "lwip/autoip.h"

typedef struct ip_hdr  ip4_hdr_t;
typedef struct ip6_hdr ip6_hdr_t;

#define NETIF_FLAG_L3TO4 0x80U // our custom flag that indicates that the netif is for the PacketToConnection node

// struct ww_netif_clientdata_first{
//     uint64_t flags;
// };

//
// ============================= Generic IP Functions =============================
//
#define ipAddrSetAny      ip_addr_set_any       /**< Set IP address to the wildcard address (either IPv4 or IPv6) */
#define ipAddrIsAny       ip_addr_isany         /**< Check if an IP address is the wildcard address */
#define ipAddrCmp         ip_addr_cmp           /**< Compare two IP addresses (both IPv4 or both IPv6) */
#define ipAddrNetcmp      ip_addr_netcmp        /**< Compare two IP addresses, considering network mask */
#define ipAddrCopyFromIp4 ip_addr_copy_from_ip4 /**< Copy an IPv4 address to a generic IP address */
#define ipAddrCopyFromIp6 ip_addr_copy_from_ip6 /**< Copy an IPv6 address to a generic IP address */
#define ipAddrCopy        ip_addr_copy          /**< Copy a generic IP address */
#define ipAddrIsV4        IP_IS_V4              /**< Check if an IP address is IPv4 */
#define ipAddrIsV6        IP_IS_V6              /**< Check if an IP address is IPv6 */

//
// ============================ IPv4 Specific Functions ============================
//
#define ip4AddrSetAny ip4_addr_set_any /**< Set IPv4 address to the wildcard address */
#define ip4AddrGetU32 ip4_addr_get_u32 /**< Get the IPv4 address as a 32-bit unsigned integer */
#define ip4AddrNetcmp ip4_addr_netcmp  /**< Compare two IPv4 addresses, considering network mask */
#define ip4AddrCopy   ip4_addr_copy    /**< Copy an IPv4 address */

//
// ============================ IPv6 Specific Functions ============================
//
#define ip6AddrSetAny ip6_addr_set_any /**< Set IPv6 address to the wildcard address */
#define ip6AddrNetcmp ip6_addr_netcmp  /**< Compare two IPv6 addresses, considering network mask */
#define ip6AddrCopyFromPacket                                                                                          \
    ip6_addr_copy_from_packed /**< Copy an IPv6 address from a packed (network byte order) representation */

#define ip6AddrNetworkToAaddress ip6addr_ntoa /**< Convert an IPv6 address to a string representation */
#define ip4AddrNetworkToAaddress ip4addr_ntoa /**< Convert an IPv4 address to a string representation */

//
// ============================= TCP/IP Initialization =============================
//
#define tcpipInit tcpip_init /**< Initialize the TCP/IP stack */

//
// ============================= Packet Buffer Functions =============================
//
#define pbufAlloc pbuf_alloc /**< Allocate a pbuf (packet buffer) */

void printIPPacketInfo(const char *prefix, const unsigned char *buffer);


#ifdef OS_WIN
#define LWIP_IPSTAT IP_STATS
#undef IP_STATS
#endif
