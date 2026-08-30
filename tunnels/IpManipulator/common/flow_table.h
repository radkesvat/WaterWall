#pragma once

#include "wwapi.h"

#include "loggers/log_rate_limiter.h"

/*
 * A bounded, sharded IPv4/TCP flow table shared by every stateful IpManipulator
 * trick.
 *
 * Design points that the packet paths rely on:
 *
 *   - The active-entry count never exceeds the configured limit. Admission to a
 *     full shard fails open; a live flow is never evicted to admit a new one.
 *   - The canonical key normalizes the two endpoints, so a forward packet and
 *     its reverse both select the same hash, the same shard and the same entry.
 *   - Lookup is average O(1) through hash buckets; expiry is a bounded min-heap
 *     pop. No packet callback ever scans the whole table.
 *   - An entry pointer is only valid while its shard mutex is held. Timed and
 *     cross-worker contexts must carry the key plus a trick generation instead.
 *   - Record destructors run with the shard mutex held: they may dispose of
 *     owned buffers but must never forward a packet or call into a tunnel.
 */

enum
{
    kIpManipulatorFlowLimitDefault  = 65536,
    kIpManipulatorFlowLimitMin      = 32,
    kIpManipulatorFlowLimitMax      = 1048576,
    kIpManipulatorFlowShardsMax     = 64,
    kIpManipulatorFlowCleanupBudget = 32,
    kIpManipulatorFlowFullWarnMs    = 5000
};

/*
 * Canonical four-tuple. The lower endpoint (by address, then port) is always
 * stored first so both directions of one connection hash identically.
 */
typedef struct ipmanipulator_flow_key_s
{
    uint32_t low_addr;
    uint32_t high_addr;
    uint16_t low_port;
    uint16_t high_port;
} ipmanipulator_flow_key_t;

typedef struct ipmanipulator_flow_entry_s
{
    struct ipmanipulator_flow_entry_s *bucket_next;
    ipmanipulator_flow_key_t           key;
    uint64_t                           deadline_ms;
    uint32_t                           bucket_index;
    uint32_t                           heap_index;
    /* Aligned trick-record storage; use ipmanipulatorFlowEntryRecord(). */
    ww_max_align_t record_storage[];
} ipmanipulator_flow_entry_t;

typedef struct ipmanipulator_flow_shard_s
{
    wmutex_t                     mutex;
    ipmanipulator_flow_entry_t **buckets;
    ipmanipulator_flow_entry_t **heap;
    uint32_t                     bucket_count;
    uint32_t                     bucket_mask;
    uint32_t                     heap_count;
    uint32_t                     count;
    uint32_t                     limit;
    atomic_log_rate_limiter_t    full_warning_limiter;
    uint64_t                     rejected_admissions;
} ipmanipulator_flow_shard_t;

/*
 * Called for a record that is about to leave the table. It must release every
 * buffer and allocation the record owns exactly once and must not forward
 * packets or invoke tunnel callbacks.
 */
typedef void (*ipmanipulator_flow_record_destructor_t)(void *record, void *context);

typedef struct ipmanipulator_flow_table_s
{
    ipmanipulator_flow_shard_t            *shards;
    const char                            *name;
    ipmanipulator_flow_record_destructor_t destructor;
    void                                  *destructor_context;
    uint64_t                               hash_seed;
    size_t                                 record_size;
    size_t                                 entry_size;
    uint32_t                               shard_count;
    uint32_t                               shard_mask;
    uint32_t                               limit;
} ipmanipulator_flow_table_t;

/*
 * Normalize a directed four-tuple into the canonical key. Forward and reverse
 * packets of one connection always produce byte-identical keys.
 */
static inline ipmanipulator_flow_key_t ipmanipulatorFlowKeyMake(uint32_t src_addr, uint16_t src_port, uint32_t dst_addr,
                                                                uint16_t dst_port)
{
    bool src_is_low = src_addr < dst_addr || (src_addr == dst_addr && src_port <= dst_port);

    return (ipmanipulator_flow_key_t) {
        .low_addr  = src_is_low ? src_addr : dst_addr,
        .high_addr = src_is_low ? dst_addr : src_addr,
        .low_port  = src_is_low ? src_port : dst_port,
        .high_port = src_is_low ? dst_port : src_port,
    };
}

static inline bool ipmanipulatorFlowKeyEquals(const ipmanipulator_flow_key_t *a, const ipmanipulator_flow_key_t *b)
{
    return a->low_addr == b->low_addr && a->high_addr == b->high_addr && a->low_port == b->low_port &&
           a->high_port == b->high_port;
}

static inline void *ipmanipulatorFlowEntryRecord(ipmanipulator_flow_entry_t *entry)
{
    assert(entry != NULL);
    return entry->record_storage;
}

/*
 * Create the bounded structures. limit must be within
 * [kIpManipulatorFlowLimitMin, kIpManipulatorFlowLimitMax]; worker_count only
 * selects the shard count. Returns false without leaking on any allocation or
 * argument failure, leaving the table safe to destroy.
 */
bool ipmanipulatorFlowTableInit(ipmanipulator_flow_table_t *table, const char *name, uint32_t limit,
                                uint32_t worker_count, size_t record_size,
                                ipmanipulator_flow_record_destructor_t destructor, void *destructor_context);

/* Releases every remaining entry through the destructor exactly once. */
void ipmanipulatorFlowTableDestroy(ipmanipulator_flow_table_t *table);

static inline bool ipmanipulatorFlowTableIsReady(const ipmanipulator_flow_table_t *table)
{
    return table != NULL && table->shards != NULL;
}

uint64_t ipmanipulatorFlowTableHash(const ipmanipulator_flow_table_t *table, const ipmanipulator_flow_key_t *key);

/* Selects the shard for key and locks it. Returns NULL if the table is unset. */
ipmanipulator_flow_shard_t *ipmanipulatorFlowTableLockShard(ipmanipulator_flow_table_t     *table,
                                                            const ipmanipulator_flow_key_t *key);
void                        ipmanipulatorFlowShardUnlock(ipmanipulator_flow_shard_t *shard);

ipmanipulator_flow_entry_t *ipmanipulatorFlowShardFind(ipmanipulator_flow_table_t     *table,
                                                       ipmanipulator_flow_shard_t     *shard,
                                                       const ipmanipulator_flow_key_t *key);

/*
 * Admits a new entry with a zeroed record. A key already present in the shard is
 * rejected: callers replacing a flow generation must explicitly reinitialize
 * or remove that entry first. Expired entries are reclaimed before a full-shard
 * decision; a full shard returns NULL without allocating or touching a live
 * flow.
 */
ipmanipulator_flow_entry_t *ipmanipulatorFlowShardReserve(ipmanipulator_flow_table_t     *table,
                                                          ipmanipulator_flow_shard_t     *shard,
                                                          const ipmanipulator_flow_key_t *key, uint64_t now_ms,
                                                          uint64_t deadline_ms);

void ipmanipulatorFlowShardTouch(ipmanipulator_flow_shard_t *shard, ipmanipulator_flow_entry_t *entry,
                                 uint64_t deadline_ms);

/* Removes the hash node and its heap node as one operation, then destroys it. */
void ipmanipulatorFlowShardRemove(ipmanipulator_flow_table_t *table, ipmanipulator_flow_shard_t *shard,
                                  ipmanipulator_flow_entry_t *entry);

/* Removes at most budget entries whose deadline has passed. Returns the count. */
uint32_t ipmanipulatorFlowShardExpire(ipmanipulator_flow_table_t *table, ipmanipulator_flow_shard_t *shard,
                                      uint64_t now_ms, uint32_t budget);

uint32_t ipmanipulatorFlowTableCount(ipmanipulator_flow_table_t *table);
