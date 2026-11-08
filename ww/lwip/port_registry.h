#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "lwip/err.h"
#include "lwip/ip_addr.h"

typedef enum ww_lwip_transport_e
{
    kWwLwipTcp,
    kWwLwipUdp
} ww_lwip_transport_t;

/* Embedded metadata only: the shared registry never traverses a foreign PCB.
 * A connected claim keeps its complete wire tuple reserved until PCB free,
 * including TCP TIME_WAIT. Distinct engines/netifs do not make a tuple unique. */
typedef struct ww_lwip_port_scope_s
{
    struct ww_lwip_port_scope_s *next;
    struct ww_lwip_port_scope_s *previous;
    ip_addr_t                    local;
    ip_addr_t                    remote;
    uint16_t                     port;
    uint16_t                     remote_port;
} ww_lwip_port_scope_t;

struct tcp_pcb;
struct udp_pcb;

void wwLwipPortsInitialize(void);
void wwLwipPortsFinalize(void);
/* Returns a reserved port, or zero after one bounded pass through the range. */
uint16_t wwLwipPortAllocate(ww_lwip_transport_t transport, uint16_t first, uint16_t last);
/* Commit a permanent assignment. Explicit binds retain their engine-local semantics.
 * reserved transfers the hold returned by Allocate; old occupancy is released atomically. */
void wwLwipPortCommit(ww_lwip_transport_t transport, uint16_t *tracked, uint16_t port, bool reserved);
void wwLwipPortRelease(ww_lwip_transport_t transport, uint16_t *tracked);
/* Atomically reject a bind overlapping a scoped claim and retain the new
 * unconnected reservation. Existing explicit binds keep their local semantics. */
bool wwLwipPortTryCommitBound(ww_lwip_transport_t transport, uint16_t *tracked, uint16_t port, const ip_addr_t *local);

typedef struct ww_lwip_port_stats_s
{
    uint64_t active;
    uint64_t peak;
    uint64_t refused;
    uint64_t scoped;
    uint64_t unscoped;
} ww_lwip_port_stats_t;
void wwLwipPortGetStats(ww_lwip_transport_t transport, ww_lwip_port_stats_t *stats);

/* Scope storage must be zero-initialized and must remain at a stable address
 * until release. Both endpoints are concrete and remote_port is nonzero.
 * Refuses overlapping unconnected reservations and identical connected tuples. */
uint16_t wwLwipPortScopeAllocate(ww_lwip_transport_t transport, ww_lwip_port_scope_t *scope, const ip_addr_t *local,
                                 const ip_addr_t *remote, uint16_t remote_port, uint16_t first, uint16_t last);
void     wwLwipPortScopeRelease(ww_lwip_transport_t transport, ww_lwip_port_scope_t *scope);
bool     wwLwipPortScopeMatches(const ww_lwip_port_scope_t *scope, const ip_addr_t *local, const ip_addr_t *remote,
                                uint16_t remote_port);

/* Owner-engine only, fresh unbound PCB with its final netif already bound.
 * Reserve the complete tuple before application routing is published or a TCP
 * SYN is emitted. The caller then connects to exactly this peer. Scoped local
 * and remote endpoints are immutable; UDP disconnect is not permitted. */
err_t wwLwipTcpBindConnected(struct tcp_pcb *pcb, const ip_addr_t *local, const ip_addr_t *remote,
                             uint16_t remote_port);
err_t wwLwipUdpBindConnected(struct udp_pcb *pcb, const ip_addr_t *local, const ip_addr_t *remote,
                             uint16_t remote_port);

uint16_t wwLwipNextIpv4Id(void);
uint32_t wwLwipNextIpv6Id(void);

#if defined(WW_LWIP_TEST_SEAM)
uint64_t wwLwipTestPortOccupancy(ww_lwip_transport_t transport, uint16_t port);
#endif
