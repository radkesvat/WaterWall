#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WW_LWIP_MIN_MEMORY_BUDGET     (1024ULL * 1024ULL)
#define WW_LWIP_DEFAULT_MEMORY_BUDGET (512ULL * 1024ULL * 1024ULL)
#ifdef WW_LWIP_MAX_TCP_FLOWS
#define WW_LWIP_DEFAULT_TCP_FLOWS WW_LWIP_MAX_TCP_FLOWS
#else
#define WW_LWIP_DEFAULT_TCP_FLOWS 65536U
#endif
#ifdef WW_LWIP_MAX_UDP_FLOWS
#define WW_LWIP_DEFAULT_UDP_FLOWS WW_LWIP_MAX_UDP_FLOWS
#else
#define WW_LWIP_DEFAULT_UDP_FLOWS 65536U
#endif
#ifdef WW_LWIP_MAX_TCP_LISTENERS
#define WW_LWIP_DEFAULT_TCP_LISTENERS WW_LWIP_MAX_TCP_LISTENERS
#else
#define WW_LWIP_DEFAULT_TCP_LISTENERS 1024U
#endif
#define WW_LWIP_DEFAULT_TCP_SEGMENTS 1048576U
#define WW_LWIP_DEFAULT_RX_WRAPPERS  262144U

typedef struct ww_lwip_capacity_config_s
{
    uint64_t memory_budget;
    uint32_t tcp_flows;
    uint32_t udp_flows;
    uint32_t tcp_listeners;
    uint32_t tcp_segments;
    uint32_t rx_wrappers;
} ww_lwip_capacity_config_t;

typedef struct ww_lwip_capacity_snapshot_s
{
    ww_lwip_capacity_config_t config;
    uint64_t                  reserved_bytes;
    uint64_t                  peak_reserved_bytes;
    uint64_t                  external_bytes;
    uint64_t                  byte_refusals;
    uint64_t                  external_refusals;
    uint64_t                  reclaimed_bytes;
    uint64_t                  recovery_headroom;
    uint64_t                  recovery_bytes;
    uint64_t                  external_recovery_bytes;
    uint64_t                  recovery_refusals;
    size_t                    pool_count;
    bool                      dynamic;
} ww_lwip_capacity_snapshot_t;

typedef struct ww_lwip_pool_snapshot_s
{
    const char *name;
    uint32_t    object_size;
    uint32_t    limit;
    uint32_t    allocated;
    /* Objects checked out from slabs, including reservations in worker caches.
     * Cached objects remain charged and are reclaimable on allocation pressure. */
    uint32_t held;
    uint32_t peak_held;
    uint64_t entry_refusals;
    uint64_t byte_refusals;
    uint64_t reserved_bytes;
} ww_lwip_pool_snapshot_t;

/* Exclusive startup, before shared lwIP initialization. The caller validates
 * configuration: memory_budget is [1 MiB, SIZE_MAX], each entry limit is nonzero.
 * The budget covers pool slab requests, their headers/alignment and externally
 * charged retained storage. It is not a process RSS cap or a promise that the
 * platform allocator can satisfy every admitted request. Heap OOM remains fatal. */
void wwLwipCapacityConfigure(const ww_lwip_capacity_config_t *config);

/* Reserve before acquiring external retained storage; release exactly once when
 * its budgeted owner frees/recycles it or transfers it out of this allocation
 * domain. Worker buffer caches and neighbour-owned storage are separate domains.
 * These calls do not need an entered worker engine. Budget refusal is recoverable
 * and transfers no ownership. */
bool wwLwipCapacityTryReserveExternal(size_t bytes);
void wwLwipCapacityReleaseExternal(size_t bytes);

/* The recovery partition remains inside memory_budget. Only validated header-
 * only TCP recovery input/output may use it. Store the reservation class with
 * each retained allocation and use the matching release, including cancellation
 * and foreign-thread frees. Ordinary traffic cannot borrow this partition. */
uint64_t wwLwipCapacityRecoveryHeadroom(void);
bool     wwLwipCapacityTryReserveExternalRecovery(size_t bytes);
void     wwLwipCapacityReleaseExternalRecovery(size_t bytes);

struct memp_desc;
/* Explicit RX wrapper fallback. Tagged allocations never enter ordinary worker
 * caches; release through the original memp_free_pool/LWIP_MEMPOOL_FREE API. */
void *wwLwipCapacityMallocRecovery(const struct memp_desc *pool);

/* Copies a bounded snapshot under shared allocator protection. Names refer to
 * process-lifetime pool descriptors. Returns the total registered pool count,
 * even if the caller's array is smaller. held includes cached free objects. */
size_t wwLwipCapacitySnapshot(ww_lwip_capacity_snapshot_t *snapshot, ww_lwip_pool_snapshot_t *pools, size_t capacity);
