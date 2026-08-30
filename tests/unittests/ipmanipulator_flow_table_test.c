/*
 * Structural tests for the bounded, sharded IpManipulator flow table.
 *
 * Everything asserted here is structural (counts, heap ordering, collision
 * chains, destructor invocations) rather than timing based, so the results do
 * not depend on machine speed.
 */

#include "wwapi.h"

#include "flow_table.h"

enum
{
    kMaxRecordIds = 4096
};

typedef struct test_record_s
{
    uint32_t id;
    uint32_t src_addr;
    uint16_t src_port;
    bool     live;
} test_record_t;

typedef void (*test_function_pointer_t)(void);

_Static_assert(_Alignof(ww_max_align_t) >= _Alignof(long double), "ww_max_align_t must align long double");
_Static_assert(_Alignof(ww_max_align_t) >= _Alignof(long long), "ww_max_align_t must align long long");
_Static_assert(_Alignof(ww_max_align_t) >= _Alignof(void *), "ww_max_align_t must align object pointers");
_Static_assert(_Alignof(ww_max_align_t) >= _Alignof(test_function_pointer_t),
               "ww_max_align_t must align function pointers");

static uint32_t destroy_calls;
static uint32_t destroy_counts[kMaxRecordIds];
static void    *expected_destructor_context;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void recordDestructor(void *record, void *context)
{
    test_record_t *test_record = (test_record_t *) record;

    require(context == expected_destructor_context, "destructor did not receive the registered context");
    require(record != NULL, "destructor received a NULL record");

    destroy_calls += 1U;
    if (test_record->id < kMaxRecordIds)
    {
        destroy_counts[test_record->id] += 1U;
    }
}

static void resetDestructorCounters(void)
{
    destroy_calls = 0;
    memoryZero(destroy_counts, sizeof(destroy_counts));
}

static ipmanipulator_flow_table_t makeTable(uint32_t limit, uint32_t worker_count)
{
    ipmanipulator_flow_table_t table = {0};

    expected_destructor_context = &destroy_calls;
    require(ipmanipulatorFlowTableInit(
                &table, "unit", limit, worker_count, sizeof(test_record_t), recordDestructor, &destroy_calls),
            "failed to initialize the flow table");
    return table;
}

static bool insertFlow(ipmanipulator_flow_table_t *table, uint32_t src_addr, uint16_t src_port, uint32_t dst_addr,
                       uint16_t dst_port, uint32_t id, uint64_t deadline_ms)
{
    ipmanipulator_flow_key_t    key   = ipmanipulatorFlowKeyMake(src_addr, src_port, dst_addr, dst_port);
    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(table, &key);

    require(shard != NULL, "failed to lock a shard for insertion");

    ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardReserve(table, shard, &key, 0, deadline_ms);
    if (entry != NULL)
    {
        test_record_t *record = (test_record_t *) ipmanipulatorFlowEntryRecord(entry);

        require((uintptr_t) record % _Alignof(ww_max_align_t) == 0, "flow-table record storage is misaligned");

        record->id       = id;
        record->src_addr = src_addr;
        record->src_port = src_port;
        record->live     = true;
    }

    ipmanipulatorFlowShardUnlock(shard);
    return entry != NULL;
}

static test_record_t lookupFlow(ipmanipulator_flow_table_t *table, uint32_t src_addr, uint16_t src_port,
                                uint32_t dst_addr, uint16_t dst_port, bool *found)
{
    ipmanipulator_flow_key_t    key    = ipmanipulatorFlowKeyMake(src_addr, src_port, dst_addr, dst_port);
    ipmanipulator_flow_shard_t *shard  = ipmanipulatorFlowTableLockShard(table, &key);
    test_record_t               result = {0};

    require(shard != NULL, "failed to lock a shard for lookup");

    ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardFind(table, shard, &key);
    *found                            = entry != NULL;
    if (entry != NULL)
    {
        result = *(test_record_t *) ipmanipulatorFlowEntryRecord(entry);
    }

    ipmanipulatorFlowShardUnlock(shard);
    return result;
}

static void verifyShardIntegrity(ipmanipulator_flow_table_t *table)
{
    for (uint32_t s = 0; s < table->shard_count; ++s)
    {
        ipmanipulator_flow_shard_t *shard = &table->shards[s];

        mutexLock(&shard->mutex);

        require(shard->heap_count == shard->count, "shard heap count and active count diverged");
        require(shard->count <= shard->limit, "shard exceeded its hard limit");

        for (uint32_t i = 0; i < shard->heap_count; ++i)
        {
            require(shard->heap[i] != NULL, "heap contains a NULL slot below its count");
            require(shard->heap[i]->heap_index == i, "heap position bookkeeping is inconsistent");

            if (i > 0)
            {
                uint32_t parent = (i - 1U) / 2U;
                require(shard->heap[parent]->deadline_ms <= shard->heap[i]->deadline_ms,
                        "min-heap ordering was violated");
            }
        }

        uint32_t chained = 0;
        for (uint32_t b = 0; b < shard->bucket_count; ++b)
        {
            for (ipmanipulator_flow_entry_t *entry = shard->buckets[b]; entry != NULL; entry = entry->bucket_next)
            {
                require(entry->bucket_index == b, "collision chain holds an entry from another bucket");
                chained += 1U;
            }
        }

        require(chained == shard->count, "collision chains and active count diverged");

        mutexUnlock(&shard->mutex);
    }
}

static void testForwardAndReverseResolveOneRecord(void)
{
    resetDestructorCounters();

    ipmanipulator_flow_table_t table = makeTable(64, 4);

    require(insertFlow(&table, 0x0A000001U, 40000, 0x0A000002U, 443, 1, 1000), "failed to admit the first flow");

    bool          found  = false;
    test_record_t record = lookupFlow(&table, 0x0A000001U, 40000, 0x0A000002U, 443, &found);
    require(found && record.id == 1, "forward lookup did not find the record");

    record = lookupFlow(&table, 0x0A000002U, 443, 0x0A000001U, 40000, &found);
    require(found && record.id == 1, "reverse lookup did not find the same record");

    require(ipmanipulatorFlowTableCount(&table) == 1, "reverse lookup created a second entry");

    ipmanipulator_flow_key_t forward_key = ipmanipulatorFlowKeyMake(0x0A000001U, 40000, 0x0A000002U, 443);
    ipmanipulator_flow_key_t reverse_key = ipmanipulatorFlowKeyMake(0x0A000002U, 443, 0x0A000001U, 40000);

    require(ipmanipulatorFlowKeyEquals(&forward_key, &reverse_key), "tuple normalization is direction dependent");
    require(ipmanipulatorFlowTableHash(&table, &forward_key) == ipmanipulatorFlowTableHash(&table, &reverse_key),
            "forward and reverse keys hash differently");

    ipmanipulator_flow_shard_t *forward_shard = ipmanipulatorFlowTableLockShard(&table, &forward_key);
    ipmanipulatorFlowShardUnlock(forward_shard);
    ipmanipulator_flow_shard_t *reverse_shard = ipmanipulatorFlowTableLockShard(&table, &reverse_key);
    ipmanipulatorFlowShardUnlock(reverse_shard);
    require(forward_shard == reverse_shard, "forward and reverse keys selected different shards");

    verifyShardIntegrity(&table);
    ipmanipulatorFlowTableDestroy(&table);
    require(destroy_calls == 1 && destroy_counts[1] == 1, "teardown did not release the entry exactly once");
}

static void testDuplicateCanonicalReservationIsRejected(void)
{
    resetDestructorCounters();

    ipmanipulator_flow_table_t table = makeTable(64, 1);

    require(insertFlow(&table, 0x0A000001U, 40000, 0x0A000002U, 443, 1, 1000),
            "failed to admit the original canonical flow");
    require(! insertFlow(&table, 0x0A000002U, 443, 0x0A000001U, 40000, 2, 2000),
            "reverse-orientation reservation created a duplicate canonical entry");
    require(ipmanipulatorFlowTableCount(&table) == 1,
            "a rejected reverse-orientation reservation changed the active count");

    bool          found  = false;
    test_record_t record = lookupFlow(&table, 0x0A000002U, 443, 0x0A000001U, 40000, &found);
    require(found && record.id == 1, "a rejected reverse-orientation reservation replaced or hid the original record");

    verifyShardIntegrity(&table);
    ipmanipulatorFlowTableDestroy(&table);
    require(destroy_calls == 1 && destroy_counts[1] == 1, "duplicate rejection changed canonical entry ownership");
}

static void testBucketCollisionsDoNotAlias(void)
{
    resetDestructorCounters();

    ipmanipulator_flow_table_t table = makeTable(64, 1);

    require(table.shard_count == 1, "the single-shard fixture unexpectedly sharded");

    ipmanipulator_flow_key_t    base_key = ipmanipulatorFlowKeyMake(0x0A000001U, 40000, 0x0A000002U, 443);
    ipmanipulator_flow_shard_t *shard    = &table.shards[0];
    uint32_t base_bucket = (uint32_t) ipmanipulatorFlowTableHash(&table, &base_key) & shard->bucket_mask;

    uint16_t colliding_port  = 0;
    uint32_t collisions_seen = 0;

    for (uint32_t port = 40001; port <= 65535U && collisions_seen == 0; ++port)
    {
        ipmanipulator_flow_key_t candidate = ipmanipulatorFlowKeyMake(0x0A000001U, (uint16_t) port, 0x0A000002U, 443);

        if (((uint32_t) ipmanipulatorFlowTableHash(&table, &candidate) & shard->bucket_mask) == base_bucket)
        {
            colliding_port  = (uint16_t) port;
            collisions_seen = 1;
        }
    }

    require(collisions_seen == 1, "could not construct a bucket collision for the current hash seed");

    require(insertFlow(&table, 0x0A000001U, 40000, 0x0A000002U, 443, 10, 1000), "failed to admit the base flow");
    require(insertFlow(&table, 0x0A000001U, colliding_port, 0x0A000002U, 443, 11, 1000),
            "failed to admit the colliding flow");
    require(ipmanipulatorFlowTableCount(&table) == 2, "a bucket collision merged two distinct flows");

    bool          found  = false;
    test_record_t record = lookupFlow(&table, 0x0A000001U, 40000, 0x0A000002U, 443, &found);
    require(found && record.id == 10 && record.src_port == 40000, "the base flow resolved to the wrong record");

    record = lookupFlow(&table, 0x0A000001U, colliding_port, 0x0A000002U, 443, &found);
    require(found && record.id == 11 && record.src_port == colliding_port,
            "the colliding flow resolved to the wrong record");

    /* Removing the chain head must keep the other colliding entry reachable. */
    ipmanipulator_flow_key_t    base_lookup = ipmanipulatorFlowKeyMake(0x0A000001U, 40000, 0x0A000002U, 443);
    ipmanipulator_flow_shard_t *locked      = ipmanipulatorFlowTableLockShard(&table, &base_lookup);
    ipmanipulator_flow_entry_t *entry       = ipmanipulatorFlowShardFind(&table, locked, &base_lookup);
    require(entry != NULL, "the base flow disappeared before removal");
    ipmanipulatorFlowShardRemove(&table, locked, entry);
    ipmanipulatorFlowShardUnlock(locked);

    require(destroy_calls == 1 && destroy_counts[10] == 1, "removal did not call the destructor exactly once");

    record = lookupFlow(&table, 0x0A000001U, colliding_port, 0x0A000002U, 443, &found);
    require(found && record.id == 11, "removing a chain head lost its colliding neighbour");

    verifyShardIntegrity(&table);
    ipmanipulatorFlowTableDestroy(&table);
    require(destroy_calls == 2 && destroy_counts[11] == 1, "teardown released the remaining entry more than once");
}

static void testLimitIsExactAndAdmissionFailsOpen(void)
{
    resetDestructorCounters();

    const uint32_t             limit = 32;
    ipmanipulator_flow_table_t table = makeTable(limit, 1);

    require(table.shard_count == 1, "the limit fixture unexpectedly sharded");
    require(table.shards[0].limit == limit, "the shard limit does not equal the configured limit");

    for (uint32_t i = 0; i < limit; ++i)
    {
        require(insertFlow(&table, 0x0A000001U, (uint16_t) (40000U + i), 0x0A000002U, 443, i, 100000),
                "an admission below the configured limit failed");
    }

    require(ipmanipulatorFlowTableCount(&table) == limit, "the table did not reach exactly the configured limit");

    uint32_t bucket_count_before = table.shards[0].bucket_count;

    require(! insertFlow(&table, 0x0A000001U, 60000, 0x0A000002U, 443, 999, 100000),
            "an admission past the configured limit succeeded");
    require(ipmanipulatorFlowTableCount(&table) == limit, "a failed admission changed the active count");
    require(table.shards[0].bucket_count == bucket_count_before, "a failed admission grew the table");
    require(destroy_calls == 0, "a failed admission evicted a live flow");

    for (uint32_t i = 0; i < limit; ++i)
    {
        bool          found  = false;
        test_record_t record = lookupFlow(&table, 0x0A000001U, (uint16_t) (40000U + i), 0x0A000002U, 443, &found);
        require(found && record.id == i, "a live flow was lost while the table was full");
    }

    /* Closing one flow must make room for exactly one new admission. */
    ipmanipulator_flow_key_t    key   = ipmanipulatorFlowKeyMake(0x0A000001U, 40000, 0x0A000002U, 443);
    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(&table, &key);
    ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardFind(&table, shard, &key);
    ipmanipulatorFlowShardRemove(&table, shard, entry);
    ipmanipulatorFlowShardUnlock(shard);

    require(insertFlow(&table, 0x0A000001U, 60000, 0x0A000002U, 443, 999, 100000),
            "a freed slot did not admit a new flow");
    require(! insertFlow(&table, 0x0A000001U, 60001, 0x0A000002U, 443, 998, 100000),
            "the table admitted past the limit again");

    verifyShardIntegrity(&table);
    ipmanipulatorFlowTableDestroy(&table);
    require(destroy_calls == limit + 1U, "teardown did not release every remaining entry exactly once");
}

static void testExpiryIsBoundedAndOrdered(void)
{
    resetDestructorCounters();

    const uint32_t             limit = 128;
    ipmanipulator_flow_table_t table = makeTable(limit, 1);

    for (uint32_t i = 0; i < 100U; ++i)
    {
        require(insertFlow(&table, 0x0A000001U, (uint16_t) (40000U + i), 0x0A000002U, 443, i, 1000U + i),
                "failed to admit an expiry fixture flow");
    }

    ipmanipulator_flow_shard_t *shard = &table.shards[0];

    mutexLock(&shard->mutex);
    uint32_t removed = ipmanipulatorFlowShardExpire(&table, shard, 100000, kIpManipulatorFlowCleanupBudget);
    mutexUnlock(&shard->mutex);

    require(removed == kIpManipulatorFlowCleanupBudget, "expiry did not stop at the cleanup budget");
    require(destroy_calls == kIpManipulatorFlowCleanupBudget, "expiry destroyed a different number of records");
    require(ipmanipulatorFlowTableCount(&table) == 100U - kIpManipulatorFlowCleanupBudget,
            "expiry removed a different number of entries than it reported");

    /* The heap must have popped the earliest deadlines first. */
    for (uint32_t i = 0; i < kIpManipulatorFlowCleanupBudget; ++i)
    {
        require(destroy_counts[i] == 1, "expiry did not remove the earliest deadlines first");
    }

    for (uint32_t i = kIpManipulatorFlowCleanupBudget; i < 100U; ++i)
    {
        require(destroy_counts[i] == 0, "expiry removed a later deadline out of order");
    }

    verifyShardIntegrity(&table);

    /* Nothing else has expired yet, so a second sweep at the same clock is a no-op. */
    mutexLock(&shard->mutex);
    uint32_t second = ipmanipulatorFlowShardExpire(&table, shard, 1000U + kIpManipulatorFlowCleanupBudget - 1U, 8);
    mutexUnlock(&shard->mutex);
    require(second == 0, "expiry removed an entry whose deadline had not passed");

    ipmanipulatorFlowTableDestroy(&table);
    require(destroy_calls == 100U, "teardown left entries unreleased");
}

static void testTouchReordersTheExpiryIndex(void)
{
    resetDestructorCounters();

    ipmanipulator_flow_table_t table = makeTable(64, 1);

    require(insertFlow(&table, 0x0A000001U, 40001, 0x0A000002U, 443, 1, 100), "failed to admit flow 1");
    require(insertFlow(&table, 0x0A000001U, 40002, 0x0A000002U, 443, 2, 200), "failed to admit flow 2");
    require(insertFlow(&table, 0x0A000001U, 40003, 0x0A000002U, 443, 3, 300), "failed to admit flow 3");

    /* Push the earliest deadline far into the future and pull the last one back. */
    ipmanipulator_flow_key_t    first_key = ipmanipulatorFlowKeyMake(0x0A000001U, 40001, 0x0A000002U, 443);
    ipmanipulator_flow_shard_t *shard     = ipmanipulatorFlowTableLockShard(&table, &first_key);
    ipmanipulatorFlowShardTouch(shard, ipmanipulatorFlowShardFind(&table, shard, &first_key), 9000);
    ipmanipulatorFlowShardUnlock(shard);

    ipmanipulator_flow_key_t third_key = ipmanipulatorFlowKeyMake(0x0A000001U, 40003, 0x0A000002U, 443);
    shard                              = ipmanipulatorFlowTableLockShard(&table, &third_key);
    ipmanipulatorFlowShardTouch(shard, ipmanipulatorFlowShardFind(&table, shard, &third_key), 50);
    ipmanipulatorFlowShardUnlock(shard);

    verifyShardIntegrity(&table);

    mutexLock(&table.shards[0].mutex);
    uint32_t removed = ipmanipulatorFlowShardExpire(&table, &table.shards[0], 60, kIpManipulatorFlowCleanupBudget);
    mutexUnlock(&table.shards[0].mutex);

    require(removed == 1, "touch did not move the updated deadline to the heap root");
    require(destroy_counts[3] == 1, "expiry removed the wrong flow after a deadline update");
    require(destroy_counts[1] == 0, "expiry removed a flow whose deadline was pushed later");

    bool    found = false;
    discard lookupFlow(&table, 0x0A000001U, 40001, 0x0A000002U, 443, &found);
    require(found, "a touched flow became unreachable");

    verifyShardIntegrity(&table);
    ipmanipulatorFlowTableDestroy(&table);
    require(destroy_calls == 3, "teardown did not release the remaining flows exactly once");
}

static void testReserveReclaimsExpiredBeforeFailing(void)
{
    resetDestructorCounters();

    const uint32_t             limit = 32;
    ipmanipulator_flow_table_t table = makeTable(limit, 1);

    for (uint32_t i = 0; i < limit; ++i)
    {
        require(insertFlow(&table, 0x0A000001U, (uint16_t) (40000U + i), 0x0A000002U, 443, i, 500),
                "failed to admit an expired-reclaim fixture flow");
    }

    ipmanipulator_flow_key_t    key   = ipmanipulatorFlowKeyMake(0x0A000001U, 60000, 0x0A000002U, 443);
    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(&table, &key);
    ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardReserve(&table, shard, &key, 100, 1000);
    ipmanipulatorFlowShardUnlock(shard);

    require(entry == NULL, "a full shard of live flows admitted a new flow");
    require(destroy_calls == 0, "a rejected admission evicted a live flow");

    /* At a clock past every deadline the same admission must reclaim and succeed. */
    shard = ipmanipulatorFlowTableLockShard(&table, &key);
    entry = ipmanipulatorFlowShardReserve(&table, shard, &key, 5000, 9000);
    if (entry != NULL)
    {
        ((test_record_t *) ipmanipulatorFlowEntryRecord(entry))->id = 999;
    }
    ipmanipulatorFlowShardUnlock(shard);

    require(entry != NULL, "a full shard of expired flows refused a new flow");
    require(destroy_calls > 0 && destroy_calls <= kIpManipulatorFlowCleanupBudget,
            "reclaiming exceeded the cleanup budget");

    verifyShardIntegrity(&table);
    ipmanipulatorFlowTableDestroy(&table);
}

static void testShardLimitsPartitionTheConfiguredLimitExactly(void)
{
    resetDestructorCounters();

    const uint32_t             limit = 1000;
    ipmanipulator_flow_table_t table = makeTable(limit, 8);
    uint32_t                   total = 0;

    require(table.shard_count == 8, "the shard count did not follow the worker count");

    for (uint32_t i = 0; i < table.shard_count; ++i)
    {
        require(table.shards[i].limit >= 1, "a shard received a zero limit");
        total += table.shards[i].limit;
    }

    require(total == limit, "shard limits do not sum to the configured limit");

    ipmanipulatorFlowTableDestroy(&table);
}

static void testProductionSeedingStaysRandom(void)
{
    ipmanipulator_flow_table_t first  = {0};
    ipmanipulator_flow_table_t second = {0};

    expected_destructor_context = NULL;

    require(ipmanipulatorFlowTableInit(&first, "seed-a", 64, 2, sizeof(test_record_t), NULL, NULL),
            "secure-seeded initialization failed");
    require(ipmanipulatorFlowTableInit(&second, "seed-b", 64, 2, sizeof(test_record_t), NULL, NULL),
            "secure-seeded initialization failed for the second table");
    require(first.hash_seed != second.hash_seed, "two secure-seeded tables shared one hash seed");

    ipmanipulatorFlowTableDestroy(&first);
    ipmanipulatorFlowTableDestroy(&second);
}

static void testInitRejectsOutOfRangeLimits(void)
{
    ipmanipulator_flow_table_t table = {0};

    expected_destructor_context = NULL;

    require(! ipmanipulatorFlowTableInit(
                &table, "too-small", kIpManipulatorFlowLimitMin - 1U, 2, sizeof(test_record_t), NULL, NULL),
            "a limit below the minimum was accepted");
    require(! ipmanipulatorFlowTableIsReady(&table), "a rejected table was left usable");

    require(! ipmanipulatorFlowTableInit(
                &table, "too-large", kIpManipulatorFlowLimitMax + 1U, 2, sizeof(test_record_t), NULL, NULL),
            "a limit above the maximum was accepted");
    require(! ipmanipulatorFlowTableIsReady(&table), "a rejected table was left usable");

    ipmanipulatorFlowTableDestroy(&table);
}

int main(void)
{
    require(globalstateInitializeSecureRandom(), "the operating system random source is unavailable");
    require(frandGlobalInit(), "fast random initialization failed");
    frandInit();

    testForwardAndReverseResolveOneRecord();
    testDuplicateCanonicalReservationIsRejected();
    testBucketCollisionsDoNotAlias();
    testLimitIsExactAndAdmissionFailsOpen();
    testExpiryIsBoundedAndOrdered();
    testTouchReordersTheExpiryIndex();
    testReserveReclaimsExpiredBeforeFailing();
    testShardLimitsPartitionTheConfiguredLimitExactly();
    testProductionSeedingStaysRandom();
    testInitRejectsOutOfRangeLimits();

    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    printf("ALL unit tests passed!\n");
    return 0;
}
