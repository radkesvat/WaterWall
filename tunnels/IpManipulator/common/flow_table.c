#include "flow_table.h"

#include "loggers/network_logger.h"

static uint32_t flowtableRoundUpPowerOfTwo(uint32_t value)
{
    if (value <= 1)
    {
        return 1;
    }

    uint32_t result = 1;
    while (result < value && result < 0x40000000U)
    {
        result <<= 1U;
    }

    return result;
}

static bool flowtableCheckedArraySize(size_t count, size_t element_size, size_t *out_size)
{
    if (count == 0 || element_size == 0 || count > SIZE_MAX / element_size)
    {
        return false;
    }

    *out_size = count * element_size;
    return true;
}

static void flowtableShardDestroyStorage(ipmanipulator_flow_shard_t *shard)
{
    memoryFree((void *) shard->buckets);
    memoryFree((void *) shard->heap);
    shard->buckets = NULL;
    shard->heap    = NULL;
}

/* ------------------------------------------------------------------ heap -- */

static void flowtableHeapSwap(ipmanipulator_flow_shard_t *shard, uint32_t a, uint32_t b)
{
    ipmanipulator_flow_entry_t *tmp = shard->heap[a];

    shard->heap[a]             = shard->heap[b];
    shard->heap[b]             = tmp;
    shard->heap[a]->heap_index = a;
    shard->heap[b]->heap_index = b;
}

static void flowtableHeapSiftUp(ipmanipulator_flow_shard_t *shard, uint32_t index)
{
    while (index > 0)
    {
        uint32_t parent = (index - 1U) / 2U;

        if (shard->heap[parent]->deadline_ms <= shard->heap[index]->deadline_ms)
        {
            return;
        }

        flowtableHeapSwap(shard, parent, index);
        index = parent;
    }
}

static void flowtableHeapSiftDown(ipmanipulator_flow_shard_t *shard, uint32_t index)
{
    for (;;)
    {
        uint32_t left     = (index * 2U) + 1U;
        uint32_t right    = left + 1U;
        uint32_t smallest = index;

        if (left < shard->heap_count && shard->heap[left]->deadline_ms < shard->heap[smallest]->deadline_ms)
        {
            smallest = left;
        }

        if (right < shard->heap_count && shard->heap[right]->deadline_ms < shard->heap[smallest]->deadline_ms)
        {
            smallest = right;
        }

        if (smallest == index)
        {
            return;
        }

        flowtableHeapSwap(shard, index, smallest);
        index = smallest;
    }
}

static void flowtableHeapPush(ipmanipulator_flow_shard_t *shard, ipmanipulator_flow_entry_t *entry)
{
    entry->heap_index              = shard->heap_count;
    shard->heap[entry->heap_index] = entry;
    shard->heap_count += 1U;
    flowtableHeapSiftUp(shard, entry->heap_index);
}

static void flowtableHeapRemoveAt(ipmanipulator_flow_shard_t *shard, uint32_t index)
{
    uint32_t last = shard->heap_count - 1U;

    if (index != last)
    {
        shard->heap[index]             = shard->heap[last];
        shard->heap[index]->heap_index = index;
    }

    shard->heap[last] = NULL;
    shard->heap_count = last;

    if (index < shard->heap_count)
    {
        flowtableHeapSiftDown(shard, index);
        flowtableHeapSiftUp(shard, index);
    }
}

/* ---------------------------------------------------------------- buckets -- */

static void flowtableBucketInsert(ipmanipulator_flow_shard_t *shard, ipmanipulator_flow_entry_t *entry,
                                  uint32_t bucket_index)
{
    entry->bucket_index          = bucket_index;
    entry->bucket_next           = shard->buckets[bucket_index];
    shard->buckets[bucket_index] = entry;
}

static void flowtableBucketRemove(ipmanipulator_flow_shard_t *shard, ipmanipulator_flow_entry_t *entry)
{
    ipmanipulator_flow_entry_t **link = &shard->buckets[entry->bucket_index];

    while (*link != NULL)
    {
        if (*link == entry)
        {
            *link              = entry->bucket_next;
            entry->bucket_next = NULL;
            return;
        }

        link = &(*link)->bucket_next;
    }
}

/* ------------------------------------------------------------ lifecycle --- */

bool ipmanipulatorFlowTableInitWithSeed(ipmanipulator_flow_table_t *table, const char *name, uint32_t limit,
                                        uint32_t worker_count, size_t record_size,
                                        ipmanipulator_flow_record_destructor_t destructor, void *destructor_context,
                                        const uint64_t *forced_seed)
{
    if (table == NULL || record_size == 0)
    {
        return false;
    }

    memoryZero(table, sizeof(*table));

    if (limit < kIpManipulatorFlowLimitMin || limit > kIpManipulatorFlowLimitMax)
    {
        LOGF("IpManipulator: %s flow limit %u is outside [%d, %d]",
             name != NULL ? name : "flow-table",
             limit,
             kIpManipulatorFlowLimitMin,
             kIpManipulatorFlowLimitMax);
        return false;
    }

    uint64_t seed = 0;
    if (forced_seed != NULL)
    {
        seed = *forced_seed;
    }
    else if (! secureRandomBytes(&seed, sizeof(seed)))
    {
        /*
         * A predictable hash lets an attacker pick tuples that all land in one
         * bucket, so refuse to run rather than fall back to a fixed seed.
         */
        LOGF("IpManipulator: %s flow table could not obtain a secure hash seed", name != NULL ? name : "flow-table");
        return false;
    }

    uint32_t shard_count = flowtableRoundUpPowerOfTwo(worker_count == 0 ? 1U : worker_count);

    if (shard_count > (uint32_t) kIpManipulatorFlowShardsMax)
    {
        shard_count = (uint32_t) kIpManipulatorFlowShardsMax;
    }

    /* Halving keeps the power of two and guarantees every shard limit is >= 1. */
    while (shard_count > limit)
    {
        shard_count >>= 1U;
    }

    if (shard_count == 0)
    {
        shard_count = 1;
    }

    size_t entry_size = 0;
    if (record_size > SIZE_MAX - sizeof(ipmanipulator_flow_entry_t))
    {
        return false;
    }
    entry_size = sizeof(ipmanipulator_flow_entry_t) + record_size;

    size_t shards_size = 0;
    if (! flowtableCheckedArraySize(shard_count, sizeof(*table->shards), &shards_size))
    {
        return false;
    }

    table->shards = memoryAllocateZero(shards_size);
    if (table->shards == NULL)
    {
        return false;
    }

    table->name               = name;
    table->destructor         = destructor;
    table->destructor_context = destructor_context;
    table->hash_seed          = seed;
    table->record_size        = record_size;
    table->entry_size         = entry_size;
    table->shard_count        = shard_count;
    table->shard_mask         = shard_count - 1U;
    table->limit              = limit;

    uint32_t base_limit = limit / shard_count;
    uint32_t remainder  = limit % shard_count;

    for (uint32_t i = 0; i < shard_count; ++i)
    {
        ipmanipulator_flow_shard_t *shard       = &table->shards[i];
        uint32_t                    shard_limit = base_limit + (i < remainder ? 1U : 0U);

        /* Every shard limit is at least one because shard_count <= limit. */
        shard->limit        = shard_limit;
        shard->bucket_count = flowtableRoundUpPowerOfTwo(shard_limit);
        shard->bucket_mask  = shard->bucket_count - 1U;
        atomicLogRateLimiterInitialize(&shard->full_warning_limiter);

        size_t buckets_size = 0;
        size_t heap_size    = 0;

        if (! flowtableCheckedArraySize(shard->bucket_count, sizeof(*shard->buckets), &buckets_size) ||
            ! flowtableCheckedArraySize(shard_limit, sizeof(*shard->heap), &heap_size))
        {
            ipmanipulatorFlowTableDestroy(table);
            return false;
        }

        shard->buckets = (ipmanipulator_flow_entry_t **) memoryAllocateZero(buckets_size);
        shard->heap    = (ipmanipulator_flow_entry_t **) memoryAllocateZero(heap_size);

        if (shard->buckets == NULL || shard->heap == NULL)
        {
            flowtableShardDestroyStorage(shard);
            ipmanipulatorFlowTableDestroy(table);
            return false;
        }

        if (UNLIKELY(! mutexTryInit(&shard->mutex)))
        {
            flowtableShardDestroyStorage(shard);
            ipmanipulatorFlowTableDestroy(table);
            return false;
        }
    }

    return true;
}

bool ipmanipulatorFlowTableInit(ipmanipulator_flow_table_t *table, const char *name, uint32_t limit,
                                uint32_t worker_count, size_t record_size,
                                ipmanipulator_flow_record_destructor_t destructor, void *destructor_context)
{
    return ipmanipulatorFlowTableInitWithSeed(
        table, name, limit, worker_count, record_size, destructor, destructor_context, NULL);
}

static void flowtableDestroyEntry(ipmanipulator_flow_table_t *table, ipmanipulator_flow_entry_t *entry)
{
    if (table->destructor != NULL)
    {
        table->destructor(ipmanipulatorFlowEntryRecord(entry), table->destructor_context);
    }

    memoryFree(entry);
}

void ipmanipulatorFlowTableDestroy(ipmanipulator_flow_table_t *table)
{
    if (table == NULL || table->shards == NULL)
    {
        return;
    }

    for (uint32_t i = 0; i < table->shard_count; ++i)
    {
        ipmanipulator_flow_shard_t *shard = &table->shards[i];

        if (shard->buckets == NULL && shard->heap == NULL)
        {
            /* Never fully constructed by a failed init; nothing to unwind. */
            continue;
        }

        mutexLock(&shard->mutex);

        for (uint32_t h = 0; h < shard->heap_count; ++h)
        {
            flowtableDestroyEntry(table, shard->heap[h]);
            shard->heap[h] = NULL;
        }

        shard->heap_count = 0;
        shard->count      = 0;

        for (uint32_t b = 0; b < shard->bucket_count; ++b)
        {
            shard->buckets[b] = NULL;
        }

        mutexUnlock(&shard->mutex);
        mutexDestroy(&shard->mutex);
        flowtableShardDestroyStorage(shard);
    }

    memoryFree(table->shards);
    memoryZero(table, sizeof(*table));
}

/* ------------------------------------------------------------ operations -- */

uint64_t ipmanipulatorFlowTableHash(const ipmanipulator_flow_table_t *table, const ipmanipulator_flow_key_t *key)
{
    /*
     * Hash the explicit fields rather than the raw structure so no padding byte
     * ever reaches the hash input.
     */
    uint8_t bytes[12];

    memoryCopy(bytes + 0, &key->low_addr, sizeof(key->low_addr));
    memoryCopy(bytes + 4, &key->high_addr, sizeof(key->high_addr));
    memoryCopy(bytes + 8, &key->low_port, sizeof(key->low_port));
    memoryCopy(bytes + 10, &key->high_port, sizeof(key->high_port));

    return (uint64_t) calcHashBytesSeed(bytes, sizeof(bytes), table->hash_seed);
}

ipmanipulator_flow_shard_t *ipmanipulatorFlowTableLockShard(ipmanipulator_flow_table_t     *table,
                                                            const ipmanipulator_flow_key_t *key)
{
    if (! ipmanipulatorFlowTableIsReady(table) || key == NULL)
    {
        return NULL;
    }

    uint64_t                    hash  = ipmanipulatorFlowTableHash(table, key);
    ipmanipulator_flow_shard_t *shard = &table->shards[(uint32_t) (hash >> 32U) & table->shard_mask];

    mutexLock(&shard->mutex);
    return shard;
}

void ipmanipulatorFlowShardUnlock(ipmanipulator_flow_shard_t *shard)
{
    if (shard != NULL)
    {
        mutexUnlock(&shard->mutex);
    }
}

static uint32_t flowtableBucketIndex(const ipmanipulator_flow_table_t *table, const ipmanipulator_flow_shard_t *shard,
                                     const ipmanipulator_flow_key_t *key)
{
    return (uint32_t) ipmanipulatorFlowTableHash(table, key) & shard->bucket_mask;
}

ipmanipulator_flow_entry_t *ipmanipulatorFlowShardFind(ipmanipulator_flow_table_t     *table,
                                                       ipmanipulator_flow_shard_t     *shard,
                                                       const ipmanipulator_flow_key_t *key)
{
    if (table == NULL || shard == NULL || key == NULL)
    {
        return NULL;
    }

    for (ipmanipulator_flow_entry_t *entry = shard->buckets[flowtableBucketIndex(table, shard, key)]; entry != NULL;
         entry                             = entry->bucket_next)
    {
        if (ipmanipulatorFlowKeyEquals(&entry->key, key))
        {
            return entry;
        }
    }

    return NULL;
}

void ipmanipulatorFlowShardRemove(ipmanipulator_flow_table_t *table, ipmanipulator_flow_shard_t *shard,
                                  ipmanipulator_flow_entry_t *entry)
{
    if (table == NULL || shard == NULL || entry == NULL)
    {
        return;
    }

    flowtableBucketRemove(shard, entry);
    flowtableHeapRemoveAt(shard, entry->heap_index);
    shard->count -= 1U;
    flowtableDestroyEntry(table, entry);
}

uint32_t ipmanipulatorFlowShardExpire(ipmanipulator_flow_table_t *table, ipmanipulator_flow_shard_t *shard,
                                      uint64_t now_ms, uint32_t budget)
{
    if (table == NULL || shard == NULL)
    {
        return 0;
    }

    uint32_t removed = 0;

    while (removed < budget && shard->heap_count > 0 && shard->heap[0]->deadline_ms <= now_ms)
    {
        ipmanipulatorFlowShardRemove(table, shard, shard->heap[0]);
        removed += 1U;
    }

    return removed;
}

ipmanipulator_flow_entry_t *ipmanipulatorFlowShardReserve(ipmanipulator_flow_table_t     *table,
                                                          ipmanipulator_flow_shard_t     *shard,
                                                          const ipmanipulator_flow_key_t *key, uint64_t now_ms,
                                                          uint64_t deadline_ms)
{
    if (table == NULL || shard == NULL || key == NULL)
    {
        return NULL;
    }

    /*
     * Canonical forward/reverse keys are intentionally identical. Reserving a
     * second node would hide the older record at the bucket head while leaving
     * its timers and owned buffers alive. Replacement is resource-specific, so
     * require the trick to cancel and reinitialize/remove the existing record.
     */
    if (ipmanipulatorFlowShardFind(table, shard, key) != NULL)
    {
        return NULL;
    }

    if (shard->count >= shard->limit)
    {
        discard ipmanipulatorFlowShardExpire(table, shard, now_ms, kIpManipulatorFlowCleanupBudget);
    }

    if (shard->count >= shard->limit)
    {
        shard->rejected_admissions += 1U;

        if (atomicLogRateLimiterShouldLogAt(&shard->full_warning_limiter, kIpManipulatorFlowFullWarnMs, now_ms))
        {
            LOGW("IpManipulator: %s flow table shard is full (%u/%u active, %llu admissions failed open so far)",
                 table->name != NULL ? table->name : "stateful",
                 shard->count,
                 shard->limit,
                 (unsigned long long) shard->rejected_admissions);
        }

        return NULL;
    }

    ipmanipulator_flow_entry_t *entry = memoryAllocateZero(table->entry_size);
    if (entry == NULL)
    {
        return NULL;
    }

    entry->key         = *key;
    entry->deadline_ms = deadline_ms;

    flowtableBucketInsert(shard, entry, flowtableBucketIndex(table, shard, key));
    flowtableHeapPush(shard, entry);
    shard->count += 1U;
    return entry;
}

void ipmanipulatorFlowShardTouch(ipmanipulator_flow_shard_t *shard, ipmanipulator_flow_entry_t *entry,
                                 uint64_t deadline_ms)
{
    if (shard == NULL || entry == NULL || entry->deadline_ms == deadline_ms)
    {
        return;
    }

    bool moved_later = deadline_ms > entry->deadline_ms;

    entry->deadline_ms = deadline_ms;

    if (moved_later)
    {
        flowtableHeapSiftDown(shard, entry->heap_index);
    }
    else
    {
        flowtableHeapSiftUp(shard, entry->heap_index);
    }
}

uint32_t ipmanipulatorFlowTableCount(ipmanipulator_flow_table_t *table)
{
    if (! ipmanipulatorFlowTableIsReady(table))
    {
        return 0;
    }

    uint32_t total = 0;

    for (uint32_t i = 0; i < table->shard_count; ++i)
    {
        mutexLock(&table->shards[i].mutex);
        total += table->shards[i].count;
        mutexUnlock(&table->shards[i].mutex);
    }

    return total;
}

void ipmanipulatorFlowTableForEach(ipmanipulator_flow_table_t *table,
                                   void (*visit)(ipmanipulator_flow_entry_t *entry, void *context), void *context)
{
    if (! ipmanipulatorFlowTableIsReady(table) || visit == NULL)
    {
        return;
    }

    for (uint32_t i = 0; i < table->shard_count; ++i)
    {
        ipmanipulator_flow_shard_t *shard = &table->shards[i];

        mutexLock(&shard->mutex);

        for (uint32_t h = 0; h < shard->heap_count; ++h)
        {
            visit(shard->heap[h], context);
        }

        mutexUnlock(&shard->mutex);
    }
}
