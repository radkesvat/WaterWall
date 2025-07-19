#pragma once

// Standard and library includes
#include "wdef.h"
#include "wexport.h"
#include "wplatform.h"


#include "lwip/autoip.h"
#include "lwip/inet_chksum.h"
#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/ip4_frag.h"
#include "lwip/ip_addr.h"
#include "lwip/pbuf.h"
#include "lwip/prot/tcp.h"
#include "lwip/tcpip.h"

#include "lwip/tcp.h"
#include "lwip/udp.h"

// ------------------------------------------------------------------------
// Type definitions and aliases
// ------------------------------------------------------------------------
typedef struct ip_hdr  ip4_hdr_t;
typedef struct ip6_hdr ip6_hdr_t;

typedef struct
{
    ip_addr_t ip;
    ip_addr_t mask;
} ipmask4_t;

typedef struct
{
    ip6_addr_t ip;
    ip6_addr_t mask;
} ipmask6_t;

typedef struct
{
    ip_addr_t ip;
    ip_addr_t mask;
} ipmask_t;

#define NETIF_FLAG_L3TO4 0x80U // Custom flag for PacketToConnection node

// ------------------------------------------------------------------------
// Generic IP Function Macros
// ------------------------------------------------------------------------
#define ipAddrSetAny           ip_addr_set_any       // Set IP address to wildcard
#define ipAddrIsAny            ip_addr_isany         // Check if IP address is wildcard
#define ipAddrCmp              ip_addr_cmp           // Compare two IP addresses
#define ipAddrNetcmp           ip_addr_netcmp        // Compare two IP addresses with mask
#define ipAddrCopyFromIp4      ip_addr_copy_from_ip4 // Copy IPv4 address to generic IP
#define ipAddrCopyFromIp6      ip_addr_copy_from_ip6 // Copy IPv6 address to generic IP
#define ipAddrCopy             ip_addr_copy          // Copy a generic IP address
#define ipAddrIsV4             IP_IS_V4              // Check if IP address is IPv4
#define ipAddrIsV6             IP_IS_V6              // Check if IP address is IPv6
#define ipAddrNetworkToAddress ipaddr_ntoa           // Convert IP address to string

// ------------------------------------------------------------------------
// IPv4 Specific Function Macros
// ------------------------------------------------------------------------
#define ip4AddrSetAny           ip4_addr_set_any
#define ip4AddrGetU32           ip4_addr_get_u32
#define ip4AddrNetcmp           ip4_addr_netcmp
#define ip4AddrCopy             ip4_addr_copy
#define ip4AddrNetworkToAddress ip4addr_ntoa
#define ip4AddrAddressToNetwork ip4addr_aton
#define ip4AddrSetU32           ip4_addr_set_u32
#define ip4AddrEqual            ip4_addr_eq

// ------------------------------------------------------------------------
// IPv6 Specific Function Macros
// ------------------------------------------------------------------------
#define ip6AddrSetAny ip6_addr_set_any
// #define ip6AddrNetcmp            ip6_addr_netcmp // Custom function is used instead, see below
#define ip6AddrCopyFromPacket   ip6_addr_copy_from_packed
#define ip6AddrNetworkToAddress ip6addr_ntoa

// ------------------------------------------------------------------------
// TCP/IP Stack Initialization Macro
// ------------------------------------------------------------------------
#define tcpipInit tcpip_init

// ------------------------------------------------------------------------
// Packet Buffer Function Macros
// ------------------------------------------------------------------------
#define pbufAlloc pbuf_alloc

// ------------------------------------------------------------------------
// Function Prototypes for Debug and Packet Info
// ------------------------------------------------------------------------
void printIPPacketInfo(const char *prefix, const unsigned char *buffer);
void printTcpPacketInfo(struct tcp_hdr *tcphdr);
void printTcpPacketFlagsInfo(u8_t flags);

// Helper function to compare two IPv6 addresses within a network mask
static inline int ip6AddrNetcmp(const ip6_addr_t *a, const ip6_addr_t *b, const ip6_addr_t *mask)
{
    int i;
    for (i = 0; i < 4; i++)
    {
        if ((a->addr[i] & mask->addr[i]) != (b->addr[i] & mask->addr[i]))
            return 0;
    }
    return 1;
}

// ------------------------------------------------------------------------
// OS-specific adjustments
// ------------------------------------------------------------------------
#ifdef OS_WIN
#define LWIP_IPSTAT IP_STATS
#undef IP_STATS

#define LWIP_ICMPSTAT ICMP_STATS
#undef ICMP_STATS

#define LWIP_TCPSTAT TCP_STATS
#undef TCP_STATS

#define LWIP_UDPSTAT UDP_STATS
#undef UDP_STATS

#define LWIP_IP6STAT IP6_STATS
#undef IP6_STATS
#endif

// pbuf stuff

/**
 * @ingroup pbuf
 * Copy (part of) the contents of a packet buffer
 * to an application supplied buffer.
 *
 * @param buf the pbuf from which to copy data
 * @param dataptr the application supplied buffer
 * @return the number of bytes copied, or 0 on failure
 */
u16_t pbufLargeCopyToPtr(const struct pbuf *buf, void *dataptr);

WW_INLINE bool addressIsIp4(const char *host)
{
    ip4_addr_t ip4;
    return ip4addr_aton(host, &ip4) != 0;
}

WW_INLINE bool addressIsIp6(const char *host)
{
    ip6_addr_t ip6;
    return ip6addr_aton(host, &ip6) != 0;
}

WW_INLINE bool addressIsIp(const char *host)
{
    return addressIsIp4(host) || addressIsIp6(host);
}

WW_INLINE uint8_t getIpVersion(char *host)
{
    if (addressIsIp4(host))
    {
        return IPADDR_TYPE_V4;
    }
    if (addressIsIp6(host))
    {
        return IPADDR_TYPE_V6;
    }
    return IPADDR_TYPE_ANY; // Not a valid IP
}

WW_INLINE int parseIpAddress(const char *ip_str, ip_addr_t *ip)
{

    if (ipaddr_aton(ip_str, ip))
    {
        if (IP_IS_V4(ip))
        {
            return IPADDR_TYPE_V4;
        }
        if (IP_IS_V6(ip))
        {
            return IPADDR_TYPE_V6;
        }
    }

    return IPADDR_TYPE_ANY; // Not a valid IP
}
