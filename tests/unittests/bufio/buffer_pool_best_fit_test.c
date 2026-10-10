/*
 * Covers: buffer pool best fit; the explicit inputs, callbacks and expected results below define this
 * suite.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Cases: testBestFitQuery, testMediumPoolGeometry, testIndependentSizing, testLowProfilePoolWidths,
 * testWorkerCacheRetention, testDevicePoolGeometry, testMasterPoolNonAllocatingCheckout
 * Checks: Assertion labels include: best-fit query rejected valid geometry; best-fit query changed pool
 * caches; best-fit query selected the wrong geometry; query test pool construction failed
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.buffer_pool_best_fit_unit
 */
#include "buffer_pool_internal.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)
#include "devices/device_pool.h"
#include "worker.h"
#include "wwapi.h"

typedef struct master_pool_probe_s
{
    unsigned seeded[2];
    unsigned created[2];
    unsigned create_calls;
    unsigned destroy_calls;
} master_pool_probe_t;

static master_pool_probe_t *master_pool_probe;

static master_pool_item_t *createMasterPoolProbeItem(void *userdata)
{
    master_pool_probe_t *probe = userdata;
    require(probe == master_pool_probe && probe->create_calls < ARRAY_SIZE(probe->created),
            "master pool created an unexpected item");
    return &probe->created[probe->create_calls++];
}

static void destroyMasterPoolProbeItem(master_pool_item_t *item)
{
    master_pool_probe_t *probe = master_pool_probe;
    require(item == &probe->seeded[0] || item == &probe->seeded[1] || item == &probe->created[0] ||
                item == &probe->created[1],
            "master pool destroyed an unknown item");
    ++probe->destroy_calls;
}

static void testMasterPoolNonAllocatingCheckout(void)
{
    /* A zero-width constructor still creates an empty usable master pool. */
    master_pool_t *pool = masterpoolCreateWithCapacity(0);
    require(pool != NULL, "master-pool fixture construction failed");
    master_pool_probe_t probe = {0};
    master_pool_probe         = &probe;
    masterpoolInstallCallBacks(pool, createMasterPoolProbeItem, destroyMasterPoolProbeItem);
    require(masterpoolTryGetItem(pool) == NULL && masterpoolTryGetItem(pool) == NULL && probe.create_calls == 0,
            "empty nonallocating checkout invoked the master creation callback");
    require(masterpoolGetCheckedOut(pool) == 0, "empty checkout changed explicit item accounting");

    master_pool_item_t *seeded[] = {&probe.seeded[0], &probe.seeded[1]};
    masterpoolReuseItems(pool, seeded, ARRAY_SIZE(seeded));
    master_pool_item_t *leased[] = {masterpoolTryGetItem(pool), masterpoolTryGetItem(pool)};
    require(leased[0] != leased[1] && (leased[0] == seeded[0] || leased[0] == seeded[1]) &&
                (leased[1] == seeded[0] || leased[1] == seeded[1]),
            "nonallocating checkout lost or duplicated a preseeded item");
    require(masterpoolTryGetItem(pool) == NULL && probe.create_calls == 0,
            "exhausted nonallocating checkout created another item");
    require(masterpoolGetCheckedOut(pool) == 0, "nonallocating checkout took over caller-owned accounting");
    masterpoolRecordCheckout(pool);
    masterpoolRecordCheckout(pool);
    require(masterpoolGetCheckedOut(pool) == 2, "explicit checkout accounting changed");
    masterpoolReuseItems(pool, leased, ARRAY_SIZE(leased));
    masterpoolRecordReturn(pool);
    masterpoolRecordReturn(pool);
    require(masterpoolGetCheckedOut(pool) == 0, "explicit return accounting did not settle");
    masterpoolMakeEmpty(pool);
    require(probe.destroy_calls == 2, "preseeded item teardown did not settle each item once");

    masterpoolGetItems(pool, leased, ARRAY_SIZE(leased), &probe);
    require(probe.create_calls == 2 && leased[0] == &probe.created[0] && leased[1] == &probe.created[1],
            "ordinary growable checkout stopped creating items on a cache miss");
    masterpoolReuseItems(pool, leased, ARRAY_SIZE(leased));
    masterpoolGetItems(pool, leased, ARRAY_SIZE(leased), &probe);
    require(probe.create_calls == 2 && leased[0] != leased[1],
            "ordinary growable checkout bypassed available cached items");
    masterpoolReuseItems(pool, leased, ARRAY_SIZE(leased));
    masterpoolMakeEmpty(pool);
    require(probe.destroy_calls == 4 && masterpoolTryGetItem(pool) == NULL && probe.create_calls == 2,
            "emptied master pool created an item or lost teardown ownership");
    masterpoolDestroy(pool);
    master_pool_probe = NULL;
}

static void checkBestFitQuery(buffer_pool_t *pool, uint32_t bytes, uint16_t padding, uint32_t expected_capacity,
                              uint16_t expected_padding, bool expected_pooled)
{
    uint32_t before[4], after[4];
    bufferpoolCachedTierCountsForTest(pool, &before[0], &before[1], &before[2], &before[3]);
    buffer_pool_fit_t fit;
    require(bufferpoolQueryBestFit(pool, bytes, padding, &fit), "best-fit query rejected valid geometry");
    bufferpoolCachedTierCountsForTest(pool, &after[0], &after[1], &after[2], &after[3]);
    require(memoryEqual(before, after, sizeof(before)), "best-fit query changed pool caches");
    require(fit.payload_capacity == expected_capacity && fit.left_padding == expected_padding &&
                fit.pooled == expected_pooled,
            "best-fit query selected the wrong geometry");

    sbuf_t *buf = bufferpoolGetBestFit(pool, bytes, padding);
    require(fit.payload_capacity == sbufGetTotalCapacityNoPadding(buf) && fit.left_padding == sbufGetLeftPadding(buf) &&
                fit.allocation_charge == sbufGetAllocationCharge(buf),
            "best-fit prediction disagrees with the actual allocation");
    bufferpoolReuseBuffer(pool, buf);
}

static void testBestFitQuery(void)
{
    master_pool_t *masters[4];
    for (size_t i = 0; i < ARRAY_SIZE(masters); ++i)
        masters[i] = masterpoolCreateWithCapacity(8);
    // Tier names need not follow capacity order for custom/device pools.
    buffer_pool_t *pool = bufferpoolCreate(masters[0], masters[1], masters[2], 2, 8192, 65536, 1024, 8192, 8192);
    require(pool != NULL, "query test pool construction failed");
    bufferpoolUpdateAllocationPaddings(pool, 64, 64, 32, 32);
    checkBestFitQuery(pool, 0, 0, 1024, 32, true);
    checkBestFitQuery(pool, 1024, 32, 1024, 32, true);
    checkBestFitQuery(pool, 1025, 32, 8192, 64, true);
    checkBestFitQuery(pool, 8193, 32, 65536, 64, true);
    checkBestFitQuery(pool, 512, 33, 8192, 64, true);
    checkBestFitQuery(pool, 512, 65, 512, 96, false);
    checkBestFitQuery(pool, 65537, 1, 65536 + kCpuLineCacheSize, 32, false);

    const buffer_pool_fit_t sentinel = {
        .allocation_charge = 123, .payload_capacity = 456, .left_padding = 7, .pooled = true};
    buffer_pool_fit_t fit = sentinel;
    require(! bufferpoolQueryBestFit(pool, UINT64_MAX, 32, &fit) &&
                ! bufferpoolQueryBestFit(pool, UINT32_MAX, 32, &fit) &&
                ! bufferpoolQueryBestFit(pool, 0, UINT16_MAX, &fit),
            "best-fit query accepted unrepresentable geometry");
    require(fit.allocation_charge == sentinel.allocation_charge && fit.payload_capacity == sentinel.payload_capacity &&
                fit.left_padding == sentinel.left_padding && fit.pooled == sentinel.pooled,
            "failed best-fit query changed its output");
    bufferpoolDestroy(pool);

    // Equal capacities prefer small, then medium, then large, subject to padding.
    pool = bufferpoolCreate(masters[0], masters[1], masters[2], 2, 4096, 4096, 4096, 4096, 4096);
    require(pool != NULL, "equal-tier query pool construction failed");
    bufferpoolUpdateAllocationPaddings(pool, 96, 64, 32, 32);
    checkBestFitQuery(pool, 4096, 0, 4096, 32, true);
    checkBestFitQuery(pool, 4096, 33, 4096, 64, true);
    checkBestFitQuery(pool, 4096, 65, 4096, 96, true);
    bufferpoolDestroy(pool);
    for (size_t i = 0; i < ARRAY_SIZE(masters); ++i)
    {
        masterpoolMakeEmpty(masters[i]);
        masterpoolDestroy(masters[i]);
    }
}

static void testMediumPoolGeometry(uint32_t large_size, uint32_t medium_size)
{
    master_pool_t *masters[4];
    for (size_t i = 0; i < ARRAY_SIZE(masters); ++i)
        masters[i] = masterpoolCreateWithCapacity(32);
    buffer_pool_t *pool = bufferpoolCreate(masters[0],
                                           masters[1],
                                           masters[2],
                                           2,
                                           large_size,
                                           medium_size,
                                           4096,
                                           min((uint32_t) (large_size), (uint32_t) SPLICE_PAYLOAD_LIMIT),
                                           large_size);
    require(pool != NULL, "medium test pool construction failed");
    bufferpoolUpdateAllocationPaddings(pool, 32, 32, 32, 32);
    checkBestFitQuery(pool, 4097, 32, medium_size, 32, true);

    sbuf_t *best = bufferpoolGetBestFit(pool, 4097, 32);
    require(sbufGetTotalCapacityNoPadding(best) == medium_size,
            "best fit skipped medium storage for a frame larger than small capacity");
    bufferpoolReuseBuffer(pool, best);
    if (large_size > medium_size)
    {
        best = bufferpoolGetBestFit(pool, medium_size + 1, 32);
        require(sbufGetTotalCapacityNoPadding(best) == large_size,
                "best fit truncated a payload above medium capacity");
        bufferpoolReuseBuffer(pool, best);
    }

    sbuf_t *buffers[16];
    for (size_t i = 0; i < ARRAY_SIZE(buffers); ++i)
    {
        buffers[i] = bufferpoolGetMediumBuffer(pool);
        require(sbufGetTotalCapacityNoPadding(buffers[i]) == medium_size, "medium size changed with large geometry");
        sbufSetLength(buffers[i], 40);
        sbufShiftLeft(buffers[i], 8);
    }
    for (size_t i = 0; i < ARRAY_SIZE(buffers); ++i)
        bufferpoolReuseBuffer(pool, buffers[i]);

    master_pool_t *retained_master = large_size == medium_size ? masters[0] : masters[1];
    require(atomicLoadRelaxed(&retained_master->len) > 0, "medium returns never reached the shared master");
    for (size_t i = 0; i < ARRAY_SIZE(buffers); ++i)
    {
        buffers[i] = bufferpoolGetMediumBuffer(pool);
        require(sbufGetLength(buffers[i]) == 0 && sbufGetLeftCapacity(buffers[i]) == 32,
                "medium reuse did not restore its length and headroom");
    }
    for (size_t i = 0; i < ARRAY_SIZE(buffers); ++i)
        bufferpoolReuseBuffer(pool, buffers[i]);

    // Shared masters may contain buffers padded for another worker/device pool.
    const uint32_t other_medium_size = medium_size == 32 * 1024 ? 64 * 1024 : 32 * 1024;
    buffer_pool_t *other             = bufferpoolCreate(masters[0],
                                            masters[1],
                                            masters[2],
                                            1,
                                            large_size,
                                            other_medium_size,
                                            4096,
                                            min((uint32_t) (large_size), (uint32_t) SPLICE_PAYLOAD_LIMIT),
                                            large_size);
    bufferpoolUpdateAllocationPaddings(other, 96, 96, 32, 32);
    sbuf_t *padded = bufferpoolGetMediumBuffer(other);
    require(sbufGetTotalCapacityNoPadding(padded) == other_medium_size && sbufGetLeftCapacity(padded) == 96,
            "shared medium checkout retained incompatible capacity or padding");
    bufferpoolReuseBuffer(other, padded);
    bufferpoolDestroy(other);
    bufferpoolDestroy(pool);
    for (size_t i = 0; i < ARRAY_SIZE(masters); ++i)
    {
        masterpoolMakeEmpty(masters[i]);
        masterpoolDestroy(masters[i]);
    }
}

static void testIndependentSizing(void)
{
    const uint32_t profiles[] = {kRamProfileS1Memory,
                                 kRamProfileS2Memory,
                                 kRamProfileM1Memory,
                                 kRamProfileM2Memory,
                                 kRamProfileL1Memory,
                                 kRamProfileL2Memory};
    for (size_t i = 0; i < ARRAY_SIZE(profiles); ++i)
    {
        master_pool_t *masters[4];
        for (size_t j = 0; j < ARRAY_SIZE(masters); ++j)
            masters[j] = masterpoolCreateWithCapacity(8);
        const bool     low          = i < 2;
        const uint32_t splice_limit = SPLICE_PAYLOAD_LIMIT;
        buffer_pool_t *pool         = bufferpoolCreate(masters[0],
                                               masters[1],
                                               masters[2],
                                               2,
                                               PROPER_LARGE_BUFFER_SIZE(profiles[i]),
                                               PROPER_MEDIUM_BUFFER_SIZE(profiles[i]),
                                               SMALL_BUFFER_SIZE,
                                               splice_limit,
                                               PROPER_WAITING_BUDGET_BASIS(profiles[i]));
        require(pool != NULL, "profile pool construction failed");
        require(bufferpoolGetLargeBufferSize(pool) == (low ? 65536 : 131072) &&
                    bufferpoolGetMediumBufferSize(pool) == (low ? 32768 : 65536) &&
                    bufferpoolGetSmallBufferSize(pool) == 4096 && bufferpoolGetSplicePayloadLimit(pool) == 1048576 &&
                    bufferpoolGetWaitingBudgetBasis(pool) == (low ? 65536 : 1048576),
                "ordinary tiers, uniform splice target or independent waiting basis differ from profile table");
        bufferpoolUpdateAllocationPaddings(pool, 64, 64, 64, 64);
        /* The Linux TUN GSO reader keeps one 64 KiB record with header bytes
         * in reserved padding: large on S1/S2, medium on higher profiles. */
        checkBestFitQuery(pool, 65536, 64, 65536, 64, true);
        buffer_pool_fit_t scratch_fit;
        require(bufferpoolQueryBestFit(pool, 65536, 64, &scratch_fit), "GSO scratch fit query failed");
        sbuf_t *scratch = sbufTryCreateWithPadding(scratch_fit.payload_capacity, scratch_fit.left_padding);
        require(scratch != NULL && sbufGetTotalCapacityNoPadding(scratch) == scratch_fit.payload_capacity &&
                    sbufGetLeftPadding(scratch) == scratch_fit.left_padding &&
                    sbufGetAllocationCharge(scratch) == scratch_fit.allocation_charge,
                "direct GSO scratch allocation disagreed with the six-profile best-fit geometry");
        sbufDestroy(scratch);
        uint32_t before[4], after[4];
        bufferpoolCachedTierCountsForTest(pool, &before[0], &before[1], &before[2], &before[3]);
        checkBestFitQuery(pool, 600 * 1024, 64, 600 * 1024, 64, false);
        bufferpoolCachedTierCountsForTest(pool, &after[0], &after[1], &after[2], &after[3]);
        require(memoryEqual(before, after, sizeof(before)), "dedicated allocation entered a pool cache");
        require(bufferpoolGetSpliceBufferStorageSize(pool) == 32, "splice target changed wrapper storage");
        bufferpoolDestroy(pool);
        require(bufferpoolCreate(masters[0], masters[1], masters[2], 2, 8192, 4096, 1024, 0, 8192) == NULL &&
                    bufferpoolCreate(masters[0], masters[1], masters[2], 2, 8192, 4096, 1024, UINT32_MAX, 8192) == NULL,
                "invalid splice limit was accepted");
        pool = bufferpoolCreate(masters[0], masters[1], masters[2], 2, 8192, 4096, 1024, 2048, 8192);
        require(pool != NULL && bufferpoolGetSplicePayloadLimit(pool) == 2048 &&
                    bufferpoolGetLargeBufferSize(pool) == 8192 && bufferpoolGetWaitingBudgetBasis(pool) == 8192,
                "custom independent splice limit changed ordinary storage");
        bufferpoolDestroy(pool);
        require(bufferpoolCreate(masters[0], masters[1], masters[2], 2, 8192, 4096, 1024, SPLICE_PAYLOAD_LIMIT, 0) ==
                        NULL &&
                    bufferpoolCreate(
                        masters[0], masters[1], masters[2], 2, 8192, 4096, 1024, SPLICE_PAYLOAD_LIMIT, UINT32_MAX) ==
                        NULL,
                "invalid waiting budget basis was accepted");
        for (size_t j = 0; j < ARRAY_SIZE(masters); ++j)
        {
            masterpoolMakeEmpty(masters[j]);
            masterpoolDestroy(masters[j]);
        }
    }
}

static void testLowProfilePoolWidths(void)
{
    const uint32_t profiles[] = {kRamProfileS1Memory, kRamProfileS2Memory};
    for (size_t i = 0; i < ARRAY_SIZE(profiles); ++i)
    {
        master_pool_t *masters[4];
        for (size_t j = 0; j < ARRAY_SIZE(masters); ++j)
            masters[j] = masterpoolCreateWithCapacity(2 * profiles[i]);
        buffer_pool_t *pool = bufferpoolCreate(masters[0],
                                               masters[1],
                                               masters[2],
                                               profiles[i],
                                               PROPER_LARGE_BUFFER_SIZE(profiles[i]),
                                               PROPER_MEDIUM_BUFFER_SIZE(profiles[i]),
                                               SMALL_BUFFER_SIZE,
                                               SPLICE_PAYLOAD_LIMIT,
                                               PROPER_WAITING_BUDGET_BASIS(profiles[i]));
        require(pool != NULL, "could not create low-profile pool");
        sbuf_t *small  = bufferpoolGetSmallBuffer(pool);
        sbuf_t *medium = bufferpoolGetMediumBuffer(pool);
        sbuf_t *large  = bufferpoolGetLargeBuffer(pool);
        require(sbufGetTotalCapacityNoPadding(small) == 4096 && sbufGetTotalCapacityNoPadding(medium) == 32 * 1024 &&
                    sbufGetTotalCapacityNoPadding(large) == 64 * 1024,
                "low-profile pool returned the wrong buffer geometry");
        uint32_t cached_large, cached_medium, cached_small, cached_splice;
        bufferpoolCachedTierCountsForTest(pool, &cached_large, &cached_small, &cached_splice, &cached_medium);
        require(cached_large == profiles[i] - 1 && cached_medium == profiles[i] - 1 && cached_small == profiles[i] - 1,
                "S1/S2 local caches did not retain their profile-based recharge counts");
        bufferpoolReuseBuffer(pool, small);
        bufferpoolReuseBuffer(pool, medium);
        bufferpoolReuseBuffer(pool, large);
        bufferpoolDestroy(pool);
        for (size_t j = 0; j < ARRAY_SIZE(masters); ++j)
        {
            masterpoolMakeEmpty(masters[j]);
            masterpoolDestroy(masters[j]);
        }
    }
}

static void testWorkerCacheRetention(void)
{
    const struct
    {
        uint32_t profile;
        uint32_t local_width;
    } cases[] = {{kRamProfileS1Memory, 1},
                 {kRamProfileS2Memory, 4},
                 {kRamProfileM1Memory, 8},
                 {kRamProfileM2Memory, 32},
                 {kRamProfileL1Memory, 64},
                 {kRamProfileL2Memory, 128}};

    for (size_t c = 0; c < ARRAY_SIZE(cases); ++c)
    {
        GSTATE.ram_profile = cases[c].profile;
        master_pool_t *masters[3];
        for (size_t i = 0; i < ARRAY_SIZE(masters); ++i)
        {
            const uint32_t width = PROPER_BUFFER_POOL_WIDTH(RAM_PROFILE);
            masters[i]           = masterpoolCreateWithCapacity(2 * width);
            require(masters[i] != NULL, "profile master construction failed");
            require(masters[i]->cap == 4 * cases[c].local_width, "profile master retained the wrong cache capacity");
        }
        GSTATE.masterpool_buffer_pools_large  = masters[0];
        GSTATE.masterpool_buffer_pools_medium = masters[1];
        GSTATE.masterpool_buffer_pools_small  = masters[2];

        worker_t worker = {0};
        require(workerTryCreateBufferPool(&worker), "worker buffer pool construction failed");
        buffer_pool_t *pool = worker.buffer_pool;
        const bool     low  = cases[c].profile < kRamProfileM1Memory;
        require(bufferpoolGetLargeBufferSize(pool) == (low ? 65536 : 131072) &&
                    bufferpoolGetMediumBufferSize(pool) == (low ? 32768 : 65536) &&
                    bufferpoolGetSmallBufferSize(pool) == 4096 && bufferpoolGetSplicePayloadLimit(pool) == 1048576 &&
                    bufferpoolGetWaitingBudgetBasis(pool) == (low ? 65536 : 1048576),
                "worker cache sizing changed buffer sizes or independent limits");

        /* Exceed both caches, then repeat to exercise refill after master overflow. */
        sbuf_t        *buffers[1024];
        const uint32_t count = 8 * cases[c].local_width;
        for (unsigned int burst = 0; burst < 2; ++burst)
        {
            for (uint32_t i = 0; i < count; ++i)
                buffers[i] = bufferpoolGetSmallBuffer(pool);
            for (uint32_t i = 0; i < count; ++i)
                bufferpoolReuseBuffer(pool, buffers[i]);

            uint32_t large, medium, small, splice;
            bufferpoolCachedTierCountsForTest(pool, &large, &small, &splice, &medium);
            require(small > 0 && small <= 4 * cases[c].local_width / 3 + 1,
                    "worker retained more idle buffers than its profile permits");
            require(large == 0 && medium == 0 && splice == 0, "small-buffer burst populated another tier");
            require(atomicLoadRelaxed(&masters[2]->len) == 4 * cases[c].local_width,
                    "burst did not fill the ordinary master to its profile limit");
        }
        bufferpoolDestroy(pool);
        for (size_t i = 0; i < ARRAY_SIZE(masters); ++i)
        {
            masterpoolMakeEmpty(masters[i]);
            masterpoolDestroy(masters[i]);
        }
    }
    GSTATE.ram_profile                    = kRamProfileInvalid;
    GSTATE.masterpool_buffer_pools_large  = NULL;
    GSTATE.masterpool_buffer_pools_medium = NULL;
    GSTATE.masterpool_buffer_pools_small  = NULL;
}

static void testDevicePoolGeometry(void)
{
    const uint32_t profiles[] = {kRamProfileS1Memory,
                                 kRamProfileS2Memory,
                                 kRamProfileM1Memory,
                                 kRamProfileM2Memory,
                                 kRamProfileL1Memory,
                                 kRamProfileL2Memory};
    for (size_t i = 0; i < ARRAY_SIZE(profiles); ++i)
    {
        GSTATE.ram_profile = profiles[i];
        master_pool_t *masters[4];
        for (size_t j = 0; j < ARRAY_SIZE(masters); ++j)
            masters[j] = masterpoolCreateWithCapacity(2 * PROPER_BUFFER_POOL_WIDTH(RAM_PROFILE));
        GSTATE.masterpool_buffer_pools_large  = masters[0];
        GSTATE.masterpool_buffer_pools_medium = masters[1];
        GSTATE.masterpool_buffer_pools_small  = masters[2];

        const bool     low    = profiles[i] < kRamProfileM1Memory;
        const uint32_t large  = low ? LARGE_BUFFER_SIZE_RAM_LOW : LARGE_BUFFER_SIZE_RAM_HIGH;
        const uint32_t medium = low ? MEDIUM_BUFFER_SIZE_RAM_LOW : MEDIUM_BUFFER_SIZE_RAM_HIGH;
        buffer_pool_t *worker = bufferpoolCreate(masters[0],
                                                 masters[1],
                                                 masters[2],
                                                 PROPER_BUFFER_POOL_WIDTH(RAM_PROFILE),
                                                 large,
                                                 medium,
                                                 4096,
                                                 123456,
                                                 654321);
        require(worker != NULL, "device geometry worker construction");
        bufferpoolUpdateAllocationPaddings(worker, 32, 64, 96, 128);
        for (uint32_t minimum = 0; minimum <= 9000; minimum += 9000)
        {
            uint32_t expected_small;
            require(sbufTryComputeCapacity(max(4096U, minimum), 0, &expected_small), "MTU geometry");
            buffer_pool_t *device = devicePoolCreate(worker, minimum);
            require(device != NULL, "device pool construction");
            require(bufferpoolGetLargeBufferSize(device) == large && bufferpoolGetMediumBufferSize(device) == medium &&
                        bufferpoolGetSmallBufferSize(device) == expected_small &&
                        bufferpoolGetSplicePayloadLimit(device) == 123456 &&
                        bufferpoolGetWaitingBudgetBasis(device) == 654321,
                    "device pool conflated tier sizes, MTU, splice limit or waiting budget");
            require(bufferpoolGetSmallBufferPadding(device) == 0, "construction captured padding too early");
            devicePoolUpdatePadding(device, worker);
            require(bufferpoolGetLargeBufferPadding(device) == bufferpoolGetLargeBufferPadding(worker) &&
                        bufferpoolGetMediumBufferPadding(device) == bufferpoolGetMediumBufferPadding(worker) &&
                        bufferpoolGetSmallBufferPadding(device) == bufferpoolGetSmallBufferPadding(worker) &&
                        bufferpoolGetSpliceBufferPadding(device) == bufferpoolGetSpliceBufferPadding(worker),
                    "device padding did not copy all four tiers");
            bufferpoolUpdateAllocationPaddings(worker, 160, 192, 224, 256);
            devicePoolUpdatePadding(device, worker);
            require(bufferpoolGetLargeBufferPadding(device) == 160 && bufferpoolGetMediumBufferPadding(device) == 192 &&
                        bufferpoolGetSmallBufferPadding(device) == 224 &&
                        bufferpoolGetSpliceBufferPadding(device) == 256,
                    "late padding growth was lost");
            bufferpoolDestroy(device);
            bufferpoolUpdateAllocationPaddings(worker, 32, 64, 96, 128);
        }

        GSTATE.masterpool_buffer_pools_medium = NULL;
        require(devicePoolCreate(worker, 0) == NULL, "device construction failure was hidden");
        bufferpoolDestroy(worker);
        for (size_t j = 0; j < ARRAY_SIZE(masters); ++j)
        {
            masterpoolMakeEmpty(masters[j]);
            masterpoolDestroy(masters[j]);
        }
        GSTATE.masterpool_buffer_pools_large = GSTATE.masterpool_buffer_pools_medium = NULL;
        GSTATE.masterpool_buffer_pools_small                                         = NULL;
    }
    GSTATE.ram_profile = kRamProfileInvalid;
}

int main(void)
{
    testCaseSet("buffer_pool_best_fit_test");
    testMasterPoolNonAllocatingCheckout();
    testDevicePoolGeometry();
    testIndependentSizing();
    testBestFitQuery();
    testLowProfilePoolWidths();
    testWorkerCacheRetention();
    const uint32_t profiles[] = {kRamProfileS1Memory,
                                 kRamProfileS2Memory,
                                 kRamProfileM1Memory,
                                 kRamProfileM2Memory,
                                 kRamProfileL1Memory,
                                 kRamProfileL2Memory};
    for (size_t i = 0; i < ARRAY_SIZE(profiles); ++i)
    {
        const bool low = profiles[i] < kRamProfileM1Memory;
        require(PROPER_LARGE_BUFFER_SIZE(profiles[i]) == (low ? 64 * 1024 : 128 * 1024),
                "profile has the wrong large-buffer capacity");
        require(PROPER_MEDIUM_BUFFER_SIZE(profiles[i]) == (low ? 32 * 1024 : 64 * 1024),
                "profile has the wrong medium-buffer capacity");
        testMediumPoolGeometry(PROPER_LARGE_BUFFER_SIZE(profiles[i]), PROPER_MEDIUM_BUFFER_SIZE(profiles[i]));
    }
    testMediumPoolGeometry(4096, 64 * 1024);
    testMediumPoolGeometry(64 * 1024, 64 * 1024);
    testMediumPoolGeometry(512 * 1024, 64 * 1024);
    master_pool_t *large_master  = masterpoolCreateWithCapacity(8);
    master_pool_t *small_master  = masterpoolCreateWithCapacity(8);
    master_pool_t *medium_master = masterpoolCreateWithCapacity(8);
    master_pool_t *splice_master = masterpoolCreateWithCapacity(8);
    buffer_pool_t *pool          = bufferpoolCreate(
        large_master, medium_master, small_master, 8, 8192, MEDIUM_BUFFER_SIZE_RAM_HIGH, 1024, 8192, 8192);
    bufferpoolUpdateAllocationPaddings(pool, 64, 64, 32, 32);

    sbuf_t *tiny = bufferpoolGetBestFit(pool, 1, 0);
    require(sbufGetTotalCapacityNoPadding(tiny) == bufferpoolGetSmallBufferSize(pool),
            "best-fit allocation selected the explicit-only splice tier");
    bufferpoolReuseBuffer(pool, tiny);

    sbuf_t *small = bufferpoolGetBestFit(pool, 512, 16);
    require(sbufGetTotalCapacityNoPadding(small) == bufferpoolGetSmallBufferSize(pool),
            "best-fit allocator did not select the small tier");
    require(sbufGetLeftPadding(small) >= 16, "small best-fit buffer lacks requested padding");
    bufferpoolReuseBuffer(pool, small);

    sbuf_t *large = bufferpoolGetBestFit(pool, 4096, 48);
    require(sbufGetTotalCapacityNoPadding(large) == bufferpoolGetLargeBufferSize(pool),
            "best-fit allocator did not select the large tier");
    require(sbufGetLeftPadding(large) >= 48, "large best-fit buffer lacks requested padding");
    bufferpoolReuseBuffer(pool, large);

    sbuf_t *padding_fallback = bufferpoolGetBestFit(pool, 512, 96);
    require(sbufGetTotalCapacityNoPadding(padding_fallback) >= 512 && sbufGetLeftPadding(padding_fallback) >= 96,
            "best-fit padding fallback does not satisfy its geometry");
    require(sbufGetTotalCapacityNoPadding(padding_fallback) != bufferpoolGetSmallBufferSize(pool) ||
                sbufGetLeftPadding(padding_fallback) != bufferpoolGetSmallBufferPadding(pool),
            "best-fit allocator returned an unsuitable pooled buffer");
    bufferpoolReuseBuffer(pool, padding_fallback);

    sbuf_t *size_fallback = bufferpoolGetBestFit(pool, 16384, 24);
    require(sbufGetTotalCapacityNoPadding(size_fallback) >= 16384 && sbufGetLeftPadding(size_fallback) >= 24,
            "best-fit size fallback does not satisfy its geometry");
    require(sbufGetTotalCapacityNoPadding(size_fallback) == MEDIUM_BUFFER_SIZE_RAM_HIGH,
            "best fit did not use the fixed medium tier above the smaller large tier");
    bufferpoolReuseBuffer(pool, size_fallback);

    sbuf_t *medium = bufferpoolGetMediumBuffer(pool);
    require(medium == size_fallback && sbufGetLength(medium) == 0 && sbufGetLeftPadding(medium) == 64,
            "medium checkout did not reuse/reset the pooled allocation");
    require(bufferpoolGetMediumBufferSize(pool) == 64 * 1024,
            "explicit medium capacity changed with the custom large-buffer size");
    bufferpoolReuseBuffer(pool, medium);
    require(bufferpoolTryGetBestFit(pool, UINT64_MAX, 64) == NULL,
            "checked best fit accepted an unrepresentable computed length");

    bufferpoolDestroy(pool);
    masterpoolMakeEmpty(large_master);
    masterpoolMakeEmpty(small_master);
    masterpoolMakeEmpty(medium_master);
    masterpoolMakeEmpty(splice_master);
    masterpoolDestroy(large_master);
    masterpoolDestroy(small_master);
    masterpoolDestroy(medium_master);
    masterpoolDestroy(splice_master);
    return 0;
}
