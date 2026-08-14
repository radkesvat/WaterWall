/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
#ifndef LWIP_LWIPOPTS_H
#define LWIP_LWIPOPTS_H

#include <wconfig.h>

// remove some duplicate definitions from lwip
#ifdef TCP_MSS
#undef TCP_MSS
#endif

#ifdef TCP_STATS
#undef TCP_STATS
#endif

#ifdef LWIP_OPTTEST_FILE
#include "lwipopts_test.h"
#else /* LWIP_OPTTEST_FILE */

#define LWIP_IPV4 1
#define LWIP_IPV6 1

#define NO_SYS         0
#define LWIP_SOCKET    (NO_SYS == 0)
#define LWIP_NETCONN   (NO_SYS == 0)
#define LWIP_NETIF_API (NO_SYS == 0)

#define LWIP_IGMP LWIP_IPV4
#define LWIP_ICMP LWIP_IPV4

#define LWIP_SNMP  LWIP_UDP
#define MIB2_STATS LWIP_SNMP
#ifdef LWIP_HAVE_MBEDTLS
#define LWIP_SNMP_V3 (LWIP_SNMP)
#endif

#define LWIP_DNS            LWIP_UDP
#define LWIP_MDNS_RESPONDER LWIP_UDP

#define LWIP_NUM_NETIF_CLIENT_DATA (LWIP_MDNS_RESPONDER)

#define LWIP_HAVE_LOOPIF        1
#define LWIP_NETIF_LOOPBACK     1
#define LWIP_LOOPBACK_MAX_PBUFS 10

#define TCP_LISTEN_BACKLOG 1

#define LWIP_COMPAT_SOCKETS 1
#define LWIP_SO_RCVTIMEO    1
#define LWIP_SO_RCVBUF      1

#define LWIP_TCPIP_CORE_LOCKING 1

#define LWIP_NETIF_LINK_CALLBACK       1
#define LWIP_NETIF_STATUS_CALLBACK     1
#define LWIP_NETIF_REMOVE_CALLBACK     1
#define LWIP_NETIF_EXT_STATUS_CALLBACK 1

#ifdef LWIP_DEBUG

#define LWIP_DBG_MIN_LEVEL 0
#define PPP_DEBUG          LWIP_DBG_OFF
#define MEM_DEBUG          LWIP_DBG_OFF
#define MEMP_DEBUG         LWIP_DBG_OFF
#define PBUF_DEBUG         LWIP_DBG_OFF
#define API_LIB_DEBUG      LWIP_DBG_OFF
#define API_MSG_DEBUG      LWIP_DBG_OFF
#define TCPIP_DEBUG        LWIP_DBG_OFF
#define NETIF_DEBUG        LWIP_DBG_OFF
#define SOCKETS_DEBUG      LWIP_DBG_OFF
#define DNS_DEBUG          LWIP_DBG_OFF
#define AUTOIP_DEBUG       LWIP_DBG_OFF
#define DHCP_DEBUG         LWIP_DBG_OFF
#define IP_DEBUG           LWIP_DBG_OFF
#define IP_REASS_DEBUG     LWIP_DBG_OFF
#define ICMP_DEBUG         LWIP_DBG_OFF
#define IGMP_DEBUG         LWIP_DBG_OFF
#define UDP_DEBUG          LWIP_DBG_OFF
#define TCP_DEBUG          LWIP_DBG_OFF
#define TCP_INPUT_DEBUG    LWIP_DBG_OFF
#define TCP_OUTPUT_DEBUG   LWIP_DBG_OFF
#define TCP_RTO_DEBUG      LWIP_DBG_OFF
#define TCP_CWND_DEBUG     LWIP_DBG_OFF
#define TCP_WND_DEBUG      LWIP_DBG_OFF
#define TCP_FR_DEBUG       LWIP_DBG_OFF
#define TCP_QLEN_DEBUG     LWIP_DBG_OFF
#define TCP_RST_DEBUG      LWIP_DBG_OFF
#endif

#define LWIP_DBG_TYPES_ON (LWIP_DBG_ON | LWIP_DBG_TRACE | LWIP_DBG_STATE | LWIP_DBG_FRESH | LWIP_DBG_HALT)

/* ---------- Memory options ---------- */
/* MEM_ALIGNMENT: should be set to the alignment of the CPU for which
   lwIP is compiled. 4 byte alignment -> define MEM_ALIGNMENT to 4, 2
   byte alignment -> define MEM_ALIGNMENT to 2. */
/* MSVC port: intel processors don't need 4-byte alignment,
   but are faster that way! */
#define MEM_ALIGNMENT     16U     // 4U

/* MEM_SIZE: the size of the heap memory. If the application will send
a lot of data that needs to be copied, this should be set high. */
#define MEM_SIZE          1000000 // 10240

/*
 * Production capacity baseline.
 *
 * These pools are global: every lwIP-using node in the process (PacketsToConnection,
 * ConnectionToPackets, WireGuardDevice, ...) draws from the same ones, and lwIP
 * allocates them statically at build time. The former development-sized values
 * (5 TCP pcbs, 8 UDP pcbs, 120 pool pbufs) let five concurrent TCP flows exhaust
 * the entire process, so they are sized for real concurrency here instead.
 *
 * WW_LWIP_MAX_TCP_FLOWS is the documented concurrency target. Override it (and
 * the pbuf/heap knobs below it) from the build to trade RAM against flow count on
 * a constrained target; the derived values keep their relative proportions.
 */
#ifndef WW_LWIP_MAX_TCP_FLOWS
#define WW_LWIP_MAX_TCP_FLOWS 2048
#endif
#ifndef WW_LWIP_MAX_UDP_FLOWS
#define WW_LWIP_MAX_UDP_FLOWS 2048
#endif

/*
 * The fragmented-datagram budget, kept separate from the flow targets on
 * purpose. Reassembly capacity is not a function of how many flows exist: it is
 * a function of how many *fragmented* datagrams may be in flight at once, and
 * multiplying it by the 2048-flow target would reserve tens of megabytes for a
 * case most topologies never hit.
 *
 * WW_LWIP_MAX_REASS_DATAGRAMS is the number of datagrams that may be
 * reassembling simultaneously. WW_LWIP_MAX_REASS_FRAGS_PER_DATAGRAM is the
 * per-datagram fragment budget the sizing assumes; 16 covers an 8 KiB datagram
 * at the smallest MTU any lwIP-using node accepts (576, whose 552-byte payload
 * quantum needs 15 fragments). Reassembly enforces this limit using
 * pbuf_clen(); return datagrams fragmented more extremely than the configured
 * budget are refused so one tuple cannot evict every peer.
 */
#ifndef WW_LWIP_MAX_REASS_DATAGRAMS
#define WW_LWIP_MAX_REASS_DATAGRAMS 32
#endif
#ifndef WW_LWIP_MAX_REASS_FRAGS_PER_DATAGRAM
#define WW_LWIP_MAX_REASS_FRAGS_PER_DATAGRAM 16
#endif
#ifndef IP_REASS_MAX_PBUFS_PER_DATAGRAM
#define IP_REASS_MAX_PBUFS_PER_DATAGRAM WW_LWIP_MAX_REASS_FRAGS_PER_DATAGRAM
#endif

/* MEMP_NUM_PBUF: the number of memp struct pbufs. If the application
   sends a lot of data out of ROM (or other static memory), this
   should be set high. */
#define MEMP_NUM_PBUF    256 // 16
/* MEMP_NUM_RAW_PCB: the number of UDP protocol control blocks. One
   per active RAW "connection". */
#define MEMP_NUM_RAW_PCB 3
/* MEMP_NUM_UDP_PCB: the number of UDP protocol control blocks. One
   per active UDP "connection". */
#define MEMP_NUM_UDP_PCB WW_LWIP_MAX_UDP_FLOWS // 8
/* MEMP_NUM_TCP_PCB: the number of simultaneously active TCP
   connections. */
#define MEMP_NUM_TCP_PCB WW_LWIP_MAX_TCP_FLOWS // 5
/* MEMP_NUM_TCP_PCB_LISTEN: the number of listening TCP connections.
   PacketsToConnection creates one pretend wildcard listener per packet worker
   that sees TCP, and core settings permit up to 254 workers, so a pool of 64
   ran out before the supported worker count did - with more than one such node
   in a chain, sooner still. The default covers every worker plus a margin for
   the other lwIP users in the process. */
#ifndef WW_LWIP_MAX_TCP_LISTENERS
#define WW_LWIP_MAX_TCP_LISTENERS 320
#endif
#define MEMP_NUM_TCP_PCB_LISTEN WW_LWIP_MAX_TCP_LISTENERS    // 8
/* MEMP_NUM_TCP_SEG: the number of simultaneously queued TCP
   segments. Sized so a meaningful share of the flows above can hold a
   full send window at once; raising MEMP_NUM_TCP_PCB alone is useless. */
#define MEMP_NUM_TCP_SEG        (16 * WW_LWIP_MAX_TCP_FLOWS) // 16
/* memp stores pool counts in a u16_t, so an over-ambitious override has to fail
   at build time rather than silently truncate the pool. The lower bounds matter
   just as much: the heap classes in lwippools.h divide the flow targets down, so
   a nonpositive override would produce empty or negative pools. */
#if (WW_LWIP_MAX_TCP_FLOWS) < 1 || (WW_LWIP_MAX_UDP_FLOWS) < 1
#error "WW_LWIP_MAX_TCP_FLOWS and WW_LWIP_MAX_UDP_FLOWS must be at least 1"
#endif
#if (WW_LWIP_MAX_REASS_DATAGRAMS) < 1 || (WW_LWIP_MAX_REASS_FRAGS_PER_DATAGRAM) < 1 ||                                 \
    (IP_REASS_MAX_PBUFS_PER_DATAGRAM) < 1
#error                                                                                                                 \
    "WW_LWIP_MAX_REASS_DATAGRAMS, WW_LWIP_MAX_REASS_FRAGS_PER_DATAGRAM, and IP_REASS_MAX_PBUFS_PER_DATAGRAM must be at least 1"
#endif
#if (WW_LWIP_MAX_TCP_LISTENERS) < 1
#error "WW_LWIP_MAX_TCP_LISTENERS must be at least 1"
#endif
#if (MEMP_NUM_TCP_SEG) > 65535 || (MEMP_NUM_TCP_PCB) > 65535 || (MEMP_NUM_UDP_PCB) > 65535 ||                          \
    (MEMP_NUM_TCP_PCB_LISTEN) > 65535
#error                                                                                                                 \
    "WW_LWIP_MAX_TCP_FLOWS / WW_LWIP_MAX_UDP_FLOWS / WW_LWIP_MAX_TCP_LISTENERS exceed what lwIP's memp pools can index"
#endif
/* The reassembly counterpart of this guard lives next to IP_REASS_MAX_PBUFS
   below: an #if here would read those still-undefined macros as zero. */
/* MEMP_NUM_SYS_TIMEOUT: the number of simultaneously active
   timeouts. */
#define MEMP_NUM_SYS_TIMEOUT        17

/* The following four are used only with the sequential API and can be
   set to 0 if the application only will use the raw API. */
/* MEMP_NUM_NETBUF: the number of struct netbufs. */
#define MEMP_NUM_NETBUF             2
/* MEMP_NUM_NETCONN: the number of struct netconns. */
#define MEMP_NUM_NETCONN            12
/* MEMP_NUM_TCPIP_MSG_*: the number of struct tcpip_msg, which is used
   for sequential API communication and incoming packets. Used in
   src/api/tcpip.c. */
#define MEMP_NUM_TCPIP_MSG_API      32 // 16
#define MEMP_NUM_TCPIP_MSG_INPKT    32 // 16

/* ---------- Pbuf options ---------- */
/* PBUF_POOL_SIZE: the number of buffers in the pbuf pool.
   This is the receive path: every packet injected into a virtual netif takes one
   (or a chain), and TCP may retain them in its out-of-order queue. Exhaustion is
   handled by dropping the affected packet, never by aborting.

   lwIP requires this to exceed IP_REASS_MAX_PBUFS, otherwise a full reassembly
   backlog would leave nothing to receive with. Three times that budget, floored
   at the previous baseline, keeps normal traffic flowing while the maximum
   number of fragments is enqueued. */
#define WW_LWIP_REASS_PBUF_HEADROOM (3 * WW_LWIP_MAX_REASS_DATAGRAMS * IP_REASS_MAX_PBUFS_PER_DATAGRAM)
#define PBUF_POOL_SIZE              ((WW_LWIP_REASS_PBUF_HEADROOM) > 1024 ? (WW_LWIP_REASS_PBUF_HEADROOM) : 1024) // 120

/* PBUF_POOL_BUFSIZE: the size of each pbuf in the pbuf pool. */
#define PBUF_POOL_BUFSIZE           1500                                                                          // 256

/** SYS_LIGHTWEIGHT_PROT
 * define SYS_LIGHTWEIGHT_PROT in lwipopts.h if you want inter-task protection
 * for certain critical regions during buffer allocation, deallocation and memory
 * allocation and deallocation.
 */
#define SYS_LIGHTWEIGHT_PROT        (NO_SYS == 0)

/* ---------- TCP options ---------- */
#define LWIP_TCP                    1
#define TCP_TTL                     255

#define LWIP_ALTCP (LWIP_TCP)
#ifdef LWIP_HAVE_MBEDTLS
#define LWIP_ALTCP_TLS         (LWIP_TCP)
#define LWIP_ALTCP_TLS_MBEDTLS (LWIP_TCP)
#endif

/* Controls if TCP should queue segments that arrive out of
   order. Define to 0 if your device is low on memory. */
#define TCP_QUEUE_OOSEQ      1

/* Out-of-order retention is per-pcb but the pools behind it are process-global,
   and lwIP's defaults for both of these are 0, meaning unlimited. On the
   PacketsToConnection receive path every retained segment also pins one custom
   pbuf wrapper, and wrapper exhaustion happens before PBUF_POOL exhaustion - so
   it does not trigger lwIP's OOSEQ reclamation, and the drops that follow can
   include the very in-order retransmission that would have freed the queue.

   A per-pcb ceiling is what keeps one reordering peer from spending the shared
   reserve. It is deliberately generous relative to a normal reordering burst
   (TCP_WND / TCP_MSS is about 14 segments) and small relative to the pool.

   The 32-pbuf limit is the effective production bound. The byte limit is a
   future-defense guard: at four receive windows it is intentionally
   unreachable with today's advertised TCP_WND, but remains explicit so a
   future window-scaling change cannot silently make OOSEQ byte retention
   unlimited. */
#define TCP_OOSEQ_MAX_PBUFS  32
#define TCP_OOSEQ_MAX_BYTES  (4 * TCP_WND)

/* TCP Maximum segment size. */
#define TCP_MSS              1460        // 1024

/* TCP sender buffer space (bytes). */
#define TCP_SND_BUF          (20 * 1024) // 2048

/* TCP sender buffer space (pbufs). This must be at least = 2 *
   TCP_SND_BUF/TCP_MSS for things to work. */
#define TCP_SND_QUEUELEN     (16 * TCP_SND_BUF / TCP_MSS)

/* TCP writable space (bytes). This must be less than or equal
   to TCP_SND_BUF. It is the amount of space which must be
   available in the tcp snd_buf for select to return writable */
#define TCP_SNDLOWAT         (TCP_SND_BUF / 2)

/* TCP receive window. */
#define TCP_WND              (20 * 1024)

/* Maximum number of retransmissions of data segments. */
#define TCP_MAXRTX           12

/* Maximum number of retransmissions of SYN segments. */
#define TCP_SYNMAXRTX        4

/* ---------- ARP options ---------- */
#define LWIP_ARP             1
#define ARP_TABLE_SIZE       10
#define ARP_QUEUEING         1

/* ---------- IP options ---------- */
/* Define IP_FORWARD to 1 if you wish to have the ability to forward
   IP packets across network interfaces. If you are going to run lwIP
   on a device with only one network interface, define this to 0. */
#define IP_FORWARD           1

/* IP reassembly and segmentation.These are orthogonal even
 * if they both deal with IP fragments */
#define IP_REASSEMBLY        1
/* MEMP_NUM_REASSDATA counts datagrams, IP_REASS_MAX_PBUFS counts the fragments
   held across all of them. They are different units and must not be set to the
   same number: one 8 KiB datagram alone needs 15 fragments at MTU 576, so a
   shared value of 10 could not reassemble a single one. */
#define MEMP_NUM_REASSDATA   WW_LWIP_MAX_REASS_DATAGRAMS
#define IP_REASS_MAX_PBUFS   (WW_LWIP_MAX_REASS_DATAGRAMS * IP_REASS_MAX_PBUFS_PER_DATAGRAM)
#define IP_FRAG              1
#define IPV6_FRAG_COPYHEADER 1

/* WW_LWIP_RX_WRAPPER_POOL_SIZE: custom-pbuf wrappers for the zero-copy receive
   path (PacketsToConnection). Every fragment lwIP retains for reassembly, and
   every segment TCP retains out of order, pins one wrapper for as long as it
   holds the pbuf, so this pool has to cover the reassembly budget rather than
   the momentary in-flight packet count.

   It is derived from the TCP flow target too, not from reassembly alone: TCP
   out-of-order retention is the larger consumer, and unlike PBUF_POOL exhaustion
   it does not trigger lwIP's OOSEQ reclamation - so a pool sized only for
   reassembly can be emptied by ordinary reordering across the advertised flow
   count and then drop the very retransmissions that would free it.

   The flow share is one wrapper per advertised flow, not a fraction of one. At
   a quarter, the reassembly allowance left 768 wrappers for 2,048 flows, so a
   single out-of-order segment on 769 of them exhausted the reserve - an ordinary
   amount of reordering, not an attack. The reassembly budget is added on top
   because it is spent by a different mechanism, and a fixed reserve on top of
   that so recovery traffic is not competing with the backlog it has to clear.

   It is still headroom rather than a hard denial-of-service bound. What makes
   the bound hard is TCP_OOSEQ_MAX_PBUFS above, which stops one peer from
   spending the whole pool; exhaustion beyond that drops one packet with a
   rate-limited warning. */
#ifndef WW_LWIP_RX_WRAPPER_POOL_SIZE
#define WW_LWIP_RX_WRAPPER_POOL_SIZE (IP_REASS_MAX_PBUFS + WW_LWIP_MAX_TCP_FLOWS + 256)
#endif

#if (IP_REASS_MAX_PBUFS) > 65535 || (PBUF_POOL_SIZE) > 65535 || (WW_LWIP_RX_WRAPPER_POOL_SIZE) > 65535
#error "WW_LWIP_MAX_REASS_DATAGRAMS exceeds what lwIP's pbuf/reassembly pools can index"
#endif
#if (PBUF_POOL_SIZE) <= (IP_REASS_MAX_PBUFS)
#error "PBUF_POOL_SIZE must exceed IP_REASS_MAX_PBUFS or a full reassembly backlog starves the receive path"
#endif

/* ---------- ICMP options ---------- */
#define ICMP_TTL              255

/* ---------- DHCP options ---------- */
/* Define LWIP_DHCP to 1 if you want DHCP configuration of
   interfaces. */
#define LWIP_DHCP             LWIP_UDP

/* 1 if you want to do an ARP check on the offered address
   (recommended). */
#define DHCP_DOES_ARP_CHECK   (LWIP_DHCP)

/* ---------- AUTOIP options ------- */
#define LWIP_AUTOIP           (LWIP_DHCP)
#define LWIP_DHCP_AUTOIP_COOP (LWIP_DHCP && LWIP_AUTOIP)

/* ---------- UDP options ---------- */
#define LWIP_UDP              1
#define LWIP_UDPLITE          LWIP_UDP
#define UDP_TTL               255

/* ---------- RAW options ---------- */
/*
 * Intentionally disabled, and intentionally not merely defaulted off.
 *
 * WaterWall's exact-netif identity work - index plus non-reusable generation on
 * every PCB, with a removal preflight - covers TCP and UDP. The patched IP_PCB
 * carries `netif_generation` for RAW PCBs too, but upstream RAW bind, input,
 * send, disconnect and address-change paths still match on the one-byte index
 * alone, so a RAW PCB can outlive its netif and then answer for whatever
 * interface inherits that index. No node in this project opens a RAW PCB.
 *
 * Turning this on therefore needs the same treatment TCP and UDP got, including
 * netconn/socket error propagation and forced-index-reuse tests - not a flag
 * flip. The guard below is what makes that a build failure rather than a silent
 * regression, and it is why exact-netif test coverage never claims RAW.
 */
#define LWIP_RAW              0

#if LWIP_RAW
#error "LWIP_RAW is unsupported: RAW PCBs lack the exact-netif generation checks TCP and UDP have"
#endif

/* ---------- Statistics options ---------- */

#define LWIP_STATS         1
#define LWIP_STATS_DISPLAY 1

#if LWIP_STATS
#define LINK_STATS   1
#define IP_STATS     1
#define ICMP_STATS   1
#define IGMP_STATS   1
#define IPFRAG_STATS 1
#define UDP_STATS    1
#define TCP_STATS    1
#define MEM_STATS    1
#define MEMP_STATS   1
#define PBUF_STATS   1
#define SYS_STATS    1
#endif /* LWIP_STATS */

/* ---------- NETBIOS options ---------- */
#define LWIP_NETBIOS_RESPOND_NAME_QUERY 1

/* ---------- PPP options ---------- */

#define PPP_SUPPORT 1 /* Set > 0 for PPP */

#if PPP_SUPPORT

#define NUM_PPP       1 /* Max PPP sessions. */

/* Select modules to enable.  Ideally these would be set in the makefile but
 * we're limited by the command line length so you need to modify the settings
 * in this file.
 */
#define PPPOE_SUPPORT 1
#define PPPOS_SUPPORT 1

#define PAP_SUPPORT    1 /* Set > 0 for PAP. */
#define CHAP_SUPPORT   1 /* Set > 0 for CHAP. */
#define MSCHAP_SUPPORT 0 /* Set > 0 for MSCHAP */
#define CBCP_SUPPORT   0 /* Set > 0 for CBCP (NOT FUNCTIONAL!) */
#define CCP_SUPPORT    0 /* Set > 0 for CCP */
#define VJ_SUPPORT     0 /* Set > 0 for VJ header compression. */
#define MD5_SUPPORT    1 /* Set > 0 for MD5 (see also CHAP) */

#endif /* PPP_SUPPORT */

#endif /* LWIP_OPTTEST_FILE */

/* The following defines must be done even in OPTTEST mode: */

#if ! defined(NO_SYS) || ! NO_SYS /* default is 0 */
void sys_check_core_locking(void);
#define LWIP_ASSERT_CORE_LOCKED() sys_check_core_locking()
#endif

#ifndef LWIP_PLATFORM_ASSERT
/* Define LWIP_PLATFORM_ASSERT to something to catch missing stdio.h includes */
void lwip_example_app_platform_assert(const char *msg, int line, const char *file);
#define LWIP_PLATFORM_ASSERT(x) lwip_example_app_platform_assert(x, __LINE__, __FILE__)
#endif

// #include "../libc/wmem.h"
// /* lwip will use our custom allocators*/
// #define MEM_CUSTOM_FREE(ptr)     memoryFree(ptr)
// #define MEM_CUSTOM_MALLOC(sz)    memoryAllocate((size_t) (sz))
// #define MEM_CUSTOM_CALLOC(n, sz) memoryAllocateZero((size_t) ((n) * (sz)))
// #define MEM_CUSTOM_ALLOCATOR     1

#define LWIP_TCPIP_CORE_LOCKING_INPUT 1

#define MEMP_USE_CUSTOM_POOLS         1
#define MEM_USE_POOLS                 1
#define MEM_USE_POOLS_TRY_BIGGER_POOL 1
#define LWIP_CHKSUM_ALGORITHM         3
#define LWIP_CHECKSUM_ON_COPY         1
#define TCP_OVERSIZE                  TCP_MSS

// MUST BE EQUAL TO SIZEOF_STRUCT_SBUF (32)
// #define LWIP_PBUF_CUSTOM_DATA u64_t custom_data[2];

// struct pbuf;
// struct netif;
// typedef signed char err_t;
// err_t wwInternalLwipIpv4Hook(struct pbuf *p, struct netif *inp);

// #define LWIP_HOOK_IP4_INPUT wwInternalLwipIpv4Hook

#endif /* LWIP_LWIPOPTS_H */
