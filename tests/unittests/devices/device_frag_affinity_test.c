/*
 * Covers: device frag affinity; the explicit inputs, callbacks and expected results below define this
 * suite.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Cases: testCompletion, testTrustedHeaderChecksum, testRejectionAndRetirement, testBounds, testRaw,
 * testIsolationAndGrowthPeak, testSharedReadersAndGlobalBudget,
 * testSharedRawResultsSurviveOtherReaders
 * Checks: Assertion labels include: premature/missing completion; length/padding lost; header not from
 * fragment zero; bad reconstructed checksum
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.device_frag_affinity_unit
 */
#include "devices/device_flow_affinity.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)
static atomic_bool forbid_fragment_pool_access;
static void        checkedFragmentPoolReuse(buffer_pool_t *pool, sbuf_t *buf)
{
    require(! atomicLoadRelaxed(&forbid_fragment_pool_access), "shared fragments recycled into a reader pool");
    bufferpoolReuseBuffer(pool, buf);
}
static sbuf_t *checkedFragmentPoolGet(buffer_pool_t *pool, uint32_t size, uint16_t padding)
{
    require(! atomicLoadRelaxed(&forbid_fragment_pool_access), "shared fragments allocated from a reader pool");
    return bufferpoolGetBestFit(pool, size, padding);
}
static bool checkedFragmentPoolFit(const buffer_pool_t *pool, uint64_t size, uint16_t padding, buffer_pool_fit_t *fit)
{
    require(! atomicLoadRelaxed(&forbid_fragment_pool_access), "shared fragments queried a reader pool");
    return bufferpoolQueryBestFit(pool, size, padding, fit);
}
static uint16_t checkedFragmentPoolPadding(buffer_pool_t *pool)
{
    require(! atomicLoadRelaxed(&forbid_fragment_pool_access), "shared fragments read padding from a reader pool");
    return bufferpoolGetLargeBufferPadding(pool);
}
#define bufferpoolReuseBuffer           checkedFragmentPoolReuse
#define bufferpoolGetBestFit            checkedFragmentPoolGet
#define bufferpoolQueryBestFit          checkedFragmentPoolFit
#define bufferpoolGetLargeBufferPadding checkedFragmentPoolPadding
#include "devices/device_frag_affinity.c"
#undef bufferpoolReuseBuffer
#undef bufferpoolGetBestFit
#undef bufferpoolQueryBestFit
#undef bufferpoolGetLargeBufferPadding
#include "devices/device_frag_affinity.h"
#include "wwapi.h"

static master_pool_t *g_large_master;
static master_pool_t *g_small_master;
static master_pool_t *g_medium_master;
static master_pool_t *g_splice_master;
static buffer_pool_t *g_pool;


static void writeIpv4Checksum(uint8_t *packet)
{
    uint32_t sum = 0;
    PUT_BE16(packet + 10, 0);
    for (uint32_t offset = 0; offset < 20; offset += 2)
    {
        sum += GET_BE16(packet + offset);
    }
    while ((sum >> 16U) != 0)
    {
        sum = (sum & UINT32_C(0xFFFF)) + (sum >> 16U);
    }
    PUT_BE16(packet + 10, (uint16_t) ~sum);
}

static sbuf_t *makeFragment(uint16_t identification, uint16_t offset_units, bool more_fragments)
{
    enum
    {
        kPayloadBytes = 64,
        kPacketBytes  = 20 + kPayloadBytes
    };

    sbuf_t *buf = bufferpoolGetLargeBuffer(g_pool);
    require(buf != NULL, "failed to allocate a fragment");
    sbufSetLength(buf, kPacketBytes);

    uint8_t *packet = sbufGetMutablePtr(buf);
    memoryZero(packet, kPacketBytes);
    packet[0] = 0x45;
    packet[8] = 64;
    packet[9] = 17;
    PUT_BE16(packet + 2, kPacketBytes);
    PUT_BE16(packet + 4, identification);
    PUT_BE16(packet + 6, (uint16_t) (offset_units | (more_fragments ? 0x2000U : 0U)));
    PUT_BE32(packet + 12, UINT32_C(0x0A000001));
    PUT_BE32(packet + 16, UINT32_C(0xC0000201));
    if (offset_units == 0)
    {
        PUT_BE16(packet + 20, 5900);
        PUT_BE16(packet + 22, 53);
    }
    writeIpv4Checksum(packet);
    return buf;
}

static device_frag_affinity_action_t offer(device_frag_affinity_table_t *table, sbuf_t *buf,
                                           device_frag_affinity_result_t *result, uint64_t now)
{
    device_frag_view_t         view   = {0};
    device_frag_parse_result_t parsed =
        deviceFragAffinityParse(sbufGetRawPtr(buf), sbufGetLength(buf), table->trusted_ipv4_header, &view);
    *result                           = (device_frag_affinity_result_t) {0};
    if (parsed == kDeviceFragParseNotFragment)
        return kDeviceFragAffinityNotFragment;
    return deviceFragOfferLocked(table, &view, parsed, buf, result, now);
}
static void testCompletion(void)
{
    const unsigned orders[][3] = {{0, 1, 2}, {2, 1, 0}, {1, 0, 2}, {2, 0, 1}};
    for (unsigned order = 0; order < ARRAY_SIZE(orders); ++order)
    {
        device_frag_affinity_table_t *table = deviceFragAffinityCreate(g_pool, kDeviceFragmentReassemble);
        device_frag_affinity_result_t result;
        for (unsigned i = 0; i < 3; ++i)
        {
            unsigned part  = orders[order][i];
            sbuf_t  *buf   = makeFragment(10, part * 8, part != 2);
            uint8_t *bytes = sbufGetMutablePtr(buf);
            for (unsigned j = 0; j < 64; ++j)
                bytes[20 + j] = (uint8_t) (part * 64 + j);
            bytes[8] = (uint8_t) (60 + part);
            writeIpv4Checksum(bytes);
            require(offer(table, buf, &result, 100) ==
                        (i == 2 ? kDeviceFragAffinityComplete : kDeviceFragAffinityStaged),
                    "premature/missing completion");
        }
        sbuf_t *whole = result.completed;
        require(whole && sbufGetLength(whole) == 212 && sbufGetLeftCapacity(whole) >= 64, "length/padding lost");
        const uint8_t *bytes = sbufGetRawPtr(whole);
        require(GET_BE16(bytes + 2) == 212 && GET_BE16(bytes + 6) == 0 && bytes[8] == 60,
                "header not from fragment zero");
        require(deviceIpv4HeaderChecksumValid(bytes, 20), "bad reconstructed checksum");
        for (unsigned j = 0; j < 192; ++j)
            require(bytes[20 + j] == (uint8_t) j, "reassembly bytes differ");
        require(table->retained_bytes == 0, "completed storage still charged");
        wid_t wid;
        require(deviceFlowAffineWID(bytes, 212, &wid), "whole packet could not be hashed");
        bufferpoolReuseBuffer(g_pool, whole);
        deviceFragAffinityDestroy(table);
    }
    sbuf_t                       *ordinary = makeFragment(20, 0, false);
    device_frag_affinity_result_t result;
    require(deviceFragAffinityOffer(NULL, sbufGetRawPtr(ordinary), sbufGetLength(ordinary), ordinary, &result) ==
                kDeviceFragAffinityNotFragment,
            "ordinary path used assembly");
    bufferpoolReuseBuffer(g_pool, ordinary);
}
static void testTrustedHeaderChecksum(void)
{
    for (unsigned trusted = 0; trusted < 2; ++trusted)
    {
        device_frag_affinity_table_t *table = deviceFragAffinityCreate(g_pool, kDeviceFragmentReassemble);
        require(table != NULL, "fragment table allocation");
        if (trusted)
            deviceFragAffinityTrustIpv4HeaderChecksum(table);
        device_frag_affinity_result_t result;
        for (unsigned part = 0; part < 2; ++part)
        {
            sbuf_t *buf = makeFragment(500, part * 8, part == 0);
            sbufGetMutablePtr(buf)[10] ^= 1;
            const device_frag_affinity_action_t expected =
                ! trusted ? kDeviceFragAffinityConsumedDrop
                          : (part == 0 ? kDeviceFragAffinityStaged : kDeviceFragAffinityComplete);
            require(deviceFragAffinityOffer(table, sbufGetRawPtr(buf), sbufGetLength(buf), buf, &result) == expected,
                    "fragment header checksum trust crossed tables");
        }
        if (trusted)
        {
            require(result.completed != NULL && sbufGetLength(result.completed) == 148,
                    "trusted fragments did not assemble");
            require(deviceIpv4HeaderChecksumValid(sbufGetRawPtr(result.completed), 20),
                    "trusted reassembly did not generate a header checksum");
            bufferpoolReuseBuffer(g_pool, result.completed);
        }
        sbuf_t *malformed = makeFragment(501, 8, true);
        sbufSetLength(malformed, 83);
        require(deviceFragAffinityOffer(table, sbufGetRawPtr(malformed), 83, malformed, &result) ==
                    kDeviceFragAffinityConsumedDrop,
                "header trust bypassed fragment bounds");
        deviceFragAffinityDestroy(table);
    }
}

static void testRejectionAndRetirement(void)
{
    device_frag_affinity_table_t *table = deviceFragAffinityCreate(g_pool, kDeviceFragmentReassemble);
    device_frag_affinity_result_t result;
    require(offer(table, makeFragment(21, 0, true), &result, 100) == kDeviceFragAffinityStaged, "zero not retained");
    sbuf_t *overlap                = makeFragment(21, 0, true);
    sbufGetMutablePtr(overlap)[25] = 99;
    require(offer(table, overlap, &result, 100) == kDeviceFragAffinityConsumedDrop, "overlap accepted");
    require(offer(table, makeFragment(21, 8, false), &result, 100) == kDeviceFragAffinityComplete,
            "overlap destroyed accepted ranges");
    require(sbufGetMutablePtr(result.completed)[25] == 0, "rejected bytes overwrote accepted data");
    bufferpoolReuseBuffer(g_pool, result.completed);
    for (unsigned kind = 0; kind < 6; ++kind)
    {
        sbuf_t  *bad = makeFragment(30 + kind, 8, true);
        uint8_t *b   = sbufGetMutablePtr(bad);
        switch (kind)
        {
        case 0:
            b[10] ^= 1;
            break;
        case 1:
            b[0] = 0x46;
            writeIpv4Checksum(b);
            break;
        case 2:
            sbufSetLength(bad, 83);
            break;
        case 3:
            PUT_BE16(b + 2, 83);
            sbufSetLength(bad, 83);
            writeIpv4Checksum(b);
            break;
        case 4:
            PUT_BE16(b + 6, 0x3fff);
            writeIpv4Checksum(b);
            break;
        case 5:
            PUT_BE16(b + 2, 20);
            sbufSetLength(bad, 20);
            writeIpv4Checksum(b);
            break;
        }
        require(offer(table, bad, &result, 200) == kDeviceFragAffinityConsumedDrop, "invalid span admitted");
        require(offer(table, makeFragment(30 + kind, 0, true), &result, 300) == kDeviceFragAffinityConsumedDrop,
                "poison retry admitted");
        require(offer(table, makeFragment(30 + kind, 0, true), &result, 15200) == kDeviceFragAffinityStaged,
                "retry extended poison");
    }
    deviceFragAffinityEndGeneration(table);
    deviceFragAffinityReleaseStagedBuffers(table);
    require(table->retained_bytes == 0, "retirement leaked storage");
    deviceFragAffinityBeginGeneration(table);
    require(offer(table, makeFragment(30, 8, false), &result, 15201) == kDeviceFragAffinityConsumedDrop,
            "new generation adopted old bytes");
    deviceFragAffinityRetireReleasePool(table);
    deviceFragAffinityDestroy(table);
}
static void testBounds(void)
{
    device_frag_affinity_table_t *table = deviceFragAffinityCreate(g_pool, kDeviceFragmentReassemble);
    device_frag_affinity_result_t result;
    unsigned                      accepted = 0;
    for (unsigned i = 0; i < 256; ++i)
    {
        device_frag_affinity_action_t action = offer(table, makeFragment(i, 8000, false), &result, 100);
        accepted += action == kDeviceFragAffinityStaged;
        require(table->retained_bytes <= kDeviceFragAffinityMaxAssemblyBytes, "sparse allocation budget exceeded");
    }
    require(accepted > 0 && accepted < 256, "sparse allocation cap not enforced");
    deviceFragSweep(table, 15100);
    require(table->retained_bytes == 0, "expiry leaked allocations");
    deviceFragSweep(table, 30100);
    for (unsigned i = 0; i < 17; ++i)
    {
        require(offer(table, makeFragment(999, i * 16, true), &result, 30200) ==
                    (i < 16 ? kDeviceFragAffinityStaged : kDeviceFragAffinityConsumedDrop),
                "range cap broken");
    }
    require(table->retained_bytes == 0, "range refusal leaked storage");
    /* Maximum IPv4 packet, sequential tiny fragments; crosses all storage tiers. */
    for (unsigned offset = 0; offset < 65515; offset += 64)
    {
        unsigned length = min(64U, 65515U - offset);
        sbuf_t  *buf    = makeFragment(1000, offset / 8, offset + length < 65515);
        sbufSetLength(buf, 20 + length);
        PUT_BE16(sbufGetMutablePtr(buf) + 2, 20 + length);
        writeIpv4Checksum(sbufGetMutablePtr(buf));
        require(offer(table, buf, &result, 30200) ==
                    (offset + length == 65515 ? kDeviceFragAffinityComplete : kDeviceFragAffinityStaged),
                "maximum datagram failed");
    }
    require(sbufGetLength(result.completed) == 65535, "maximum packet truncated");
    bufferpoolReuseBuffer(g_pool, result.completed);
    deviceFragAffinityDestroy(table);
}
static void testRaw(void)
{
    device_frag_affinity_table_t *table = deviceFragAffinityCreate(g_pool, kDeviceFragmentPreserve);
    device_frag_affinity_result_t result;
    sbuf_t                       *tail = makeFragment(42, 8, false);
    uint8_t                       saved[84];
    memoryCopy(saved, sbufGetRawPtr(tail), 84);
    require(offer(table, tail, &result, 100) == kDeviceFragAffinityStaged, "raw tail not staged");
    sbuf_t *zero = makeFragment(42, 0, true);
    require(offer(table, zero, &result, 100) == kDeviceFragAffinityDispatch, "raw zero not dispatched");
    require(result.released_count == 1 && result.released[0] == tail, "raw staging order changed");
    require(memcmp(saved, sbufGetRawPtr(tail), 84) == 0, "raw bytes changed");
    require(table->retained_bytes == 0, "raw dispatch charged released storage");
    bufferpoolReuseBuffer(g_pool, tail);
    bufferpoolReuseBuffer(g_pool, zero);
    deviceFragAffinityDestroy(table);
}

static void testWholeFingerprintAndWorkerAreIndependent(void)
{
    const uint8_t  protocols[] = {6, 17, 132, 50};
    const unsigned counts[]    = {1, 3, 7, 16, 254};
    for (unsigned p = 0; p < ARRAY_SIZE(protocols); ++p)
    {
        sbuf_t  *buf    = makeFragment(42, 0, true);
        uint8_t *packet = sbufGetMutablePtr(buf);
        packet[9]       = protocols[p];
        PUT_BE16(packet + 20, 40000);
        PUT_BE16(packet + 22, 443);
        const uint16_t fragments = GET_BE16(packet + 6);
        PUT_BE16(packet + 6, 0);
        uint64_t fingerprint;
        uint32_t worker_hash;
        require(deviceFlowAffinityHash(packet, sbufGetLength(buf), &fingerprint) &&
                    deviceFlowWorkerHash(packet, sbufGetLength(buf), &worker_hash),
                "whole fragment tuple could not be hashed");
        PUT_BE16(packet + 6, fragments);
        for (unsigned c = 0; c < ARRAY_SIZE(counts); ++c)
        {
            GSTATE.workers_count = counts[c];
            uint64_t actual_fingerprint;
            wid_t    actual_worker;
            require(deviceFragAffinityHashAsWhole(packet, sbufGetLength(buf), &actual_fingerprint, &actual_worker),
                    "fragment-zero fingerprint/worker calculation failed");
            require(actual_fingerprint == fingerprint && actual_worker == worker_hash % counts[c],
                    "fragment-zero worker used its full64 consistency fingerprint");
            require(GET_BE16(packet + 6) == fragments, "fragment-zero hashing did not restore fragment bits");
        }
        PUT_BE16(packet + 2, 19);
        uint64_t ignored_hash;
        wid_t    ignored_wid;
        require(! deviceFragAffinityHashAsWhole(packet, sbufGetLength(buf), &ignored_hash, &ignored_wid) &&
                    GET_BE16(packet + 6) == fragments,
                "failed fragment-zero parsing did not restore fragment bits");
        bufferpoolReuseBuffer(g_pool, buf);
    }
    GSTATE.workers_count = 4;
}

static void testIsolationAndGrowthPeak(void)
{
    device_frag_affinity_table_t *a = deviceFragAffinityCreate(g_pool, kDeviceFragmentReassemble);
    device_frag_affinity_table_t *b = deviceFragAffinityCreate(g_pool, kDeviceFragmentReassemble);
    device_frag_affinity_result_t result;
    for (unsigned session = 0; session < 2; ++session)
    {
        sbuf_t *buf = makeFragment(123, 0, true);
        memset(sbufGetMutablePtr(buf) + 20, session ? 0x22 : 0x11, 64);
        require(offer(session ? b : a, buf, &result, 0) == kDeviceFragAffinityStaged, "isolation zero failed");
    }
    for (unsigned session = 0; session < 2; ++session)
    {
        require(offer(session ? b : a, makeFragment(123, 8, false), &result, 0) == kDeviceFragAffinityComplete,
                "isolated completion failed");
        require(sbufGetMutablePtr(result.completed)[20] == (session ? 0x22 : 0x11), "sessions mixed fragments");
        uint32_t hash;
        require(deviceFlowWorkerHash(sbufGetRawPtr(result.completed), 148, &hash), "complete worker hash failed");
        sbuf_t *equivalent = sbufDuplicate(result.completed);
        wid_t   wid;
        require(deviceFlowAffineWID(sbufGetRawPtr(equivalent), 148, &wid) && wid == hash % getWorkersCount(),
                "complete flow worker differs");
        sbufDestroy(equivalent);
        bufferpoolReuseBuffer(g_pool, result.completed);
    }
    deviceFragAffinityDestroy(b);
    /* 62 maximum-sized sparse buffers, one medium assembly, seven small ones.
     * The replacement would fit after freeing old storage, but its allocation
     * peak must be refused while both allocations would coexist. */
    for (unsigned i = 0; i < 62; ++i)
        require(offer(a, makeFragment(i, 8000, false), &result, 0) == kDeviceFragAffinityStaged, "peak filler failed");
    require(offer(a, makeFragment(100, 2000, true), &result, 0) == kDeviceFragAffinityStaged, "medium assembly failed");
    for (unsigned i = 0; i < 7; ++i)
        require(offer(a, makeFragment(200 + i, 8, true), &result, 0) == kDeviceFragAffinityStaged,
                "small filler failed");
    buffer_pool_fit_t old_fit, new_fit;
    require(bufferpoolQueryBestFit(g_pool, 16084, 64, &old_fit) && bufferpoolQueryBestFit(g_pool, 64084, 64, &new_fit),
            "fit query failed");
    require(a->retained_bytes + new_fit.allocation_charge > kDeviceFragAffinityMaxAssemblyBytes &&
                a->retained_bytes - old_fit.allocation_charge + new_fit.allocation_charge <=
                    kDeviceFragAffinityMaxAssemblyBytes,
            "peak fixture does not straddle budget");
    size_t before = a->retained_bytes;
    require(offer(a, makeFragment(100, 8000, false), &result, 0) == kDeviceFragAffinityConsumedDrop,
            "growth ignored old-plus-new peak");
    require(a->retained_bytes == before - old_fit.allocation_charge, "growth refusal charge not released");
    deviceFragAffinityDestroy(a);

    a = deviceFragAffinityCreate(g_pool, kDeviceFragmentReassemble);
    for (unsigned i = 0; i < kDeviceFragAffinityMaxEntries; ++i)
        require(offer(a, makeFragment(i, 8, true), &result, 0) == kDeviceFragAffinityStaged,
                "entry admission failed early");
    require(offer(a, makeFragment(1000, 8, true), &result, 0) == kDeviceFragAffinityConsumedDrop, "entry cap exceeded");
    deviceFragAffinityDestroy(a);
}

enum
{
    kSharedFragmentDatagrams = 64
};
typedef struct shared_fragment_probe_s
{
    device_frag_affinity_table_t *table;
    atomic_uint                  *arrivals;
    atomic_uint                  *completed;
    sbuf_t                       *fragments[kSharedFragmentDatagrams];
    sbuf_t                       *ordinary[kSharedFragmentDatagrams];
} shared_fragment_probe_t;

static WTHREAD_ROUTINE(offerSharedFragments)
{
    shared_fragment_probe_t *probe = userdata;
    for (unsigned i = 0; i < kSharedFragmentDatagrams; ++i)
    {
        atomicAddExplicit(&probe->arrivals[i], 1, memory_order_acq_rel);
        const uint64_t deadline = getHRTimeUs() + UINT64_C(2000000);
        while (atomicLoadExplicit(&probe->arrivals[i], memory_order_acquire) != 2)
        {
            require(getHRTimeUs() < deadline, "shared fragment reader did not reach rendezvous");
            YIELD_THREAD();
        }
        sbuf_t *ordinary = probe->ordinary[i];
        uint8_t ordinary_bytes[84];
        require(sbufGetLength(ordinary) == sizeof(ordinary_bytes), "ordinary shared-reader fixture length");
        memoryCopy(ordinary_bytes, sbufGetRawPtr(ordinary), sizeof(ordinary_bytes));
        const void *ordinary_storage = sbufGetRawPtr(ordinary);
        wid_t       ordinary_wid;
        require(deviceFlowAffineWID(ordinary_bytes, sizeof(ordinary_bytes), &ordinary_wid),
                "ordinary shared-reader packet lost its processing worker");
        device_frag_affinity_result_t ordinary_result;
        require(deviceFragAffinityOffer(
                    probe->table, sbufGetRawPtr(ordinary), sbufGetLength(ordinary), ordinary, &ordinary_result) ==
                    kDeviceFragAffinityNotFragment,
                "shared fragment table consumed an interleaved ordinary packet");
        require(ordinary_result.completed == NULL && ordinary_result.released_count == 0,
                "ordinary shared-reader packet released fragment storage");
        sbuf_t                             *buf = probe->fragments[i];
        device_frag_affinity_result_t       result;
        const device_frag_affinity_action_t action =
            deviceFragAffinityOffer(probe->table, sbufGetRawPtr(buf), sbufGetLength(buf), buf, &result);
        require(action == kDeviceFragAffinityStaged || action == kDeviceFragAffinityComplete,
                "concurrent readers lost a non-overlapping fragment");
        if (action == kDeviceFragAffinityComplete)
        {
            require(sbufGetLength(result.completed) == 148 && sbufGetLeftCapacity(result.completed) >= 96,
                    "shared reassembly lost its complete length or configured padding");
            const uint8_t *bytes = sbufGetRawPtr(result.completed);
            for (unsigned byte = 0; byte < 128; ++byte)
                require(bytes[20 + byte] == (uint8_t) (i + byte), "concurrent readers mixed fragment payloads");
            require(deviceIpv4HeaderChecksumValid(bytes, 20), "shared reassembly emitted an invalid header");
            wid_t completed_wid;
            require(deviceFlowAffineWID(bytes, sbufGetLength(result.completed), &completed_wid) &&
                        completed_wid == ordinary_wid,
                    "ordinary and reassembled packets selected different processing workers");
            sbufDestroy(result.completed);
            atomicAddExplicit(probe->completed, 1, memory_order_relaxed);
        }
        require(sbufGetRawPtr(ordinary) == ordinary_storage && sbufGetLength(ordinary) == sizeof(ordinary_bytes) &&
                    memcmp(sbufGetRawPtr(ordinary), ordinary_bytes, sizeof(ordinary_bytes)) == 0,
                "fragment interleaving modified caller-owned ordinary packet storage");
        sbufDestroy(ordinary);
    }
    return 0;
}

static void testSharedReadersAndGlobalBudget(void)
{
    device_frag_affinity_table_t *table = deviceFragAffinityCreate(g_pool, kDeviceFragmentReassemble);
    deviceFragAffinityEnableShared(table, 96);
    atomic_uint             arrivals[kSharedFragmentDatagrams] = {0};
    atomic_uint             completed                          = 0;
    shared_fragment_probe_t probes[2]                          = {
        {.table = table, .arrivals = arrivals, .completed = &completed},
        {.table = table, .arrivals = arrivals, .completed = &completed},
    };
    for (unsigned reader = 0; reader < 2; ++reader)
        for (unsigned i = 0; i < kSharedFragmentDatagrams; ++i)
        {
            sbuf_t *buf = makeFragment(2000 + i, reader * 8, reader == 0);
            for (unsigned byte = 0; byte < 64; ++byte)
                sbufGetMutablePtr(buf)[20 + byte] = (uint8_t) (i + reader * 64 + byte);
            probes[reader].fragments[i] = buf;
            sbuf_t *ordinary            = makeFragment(2000 + i, 0, false);
            for (unsigned byte = 0; byte < 64; ++byte)
                sbufGetMutablePtr(ordinary)[20 + byte] = (uint8_t) (i + byte);
            probes[reader].ordinary[i] = ordinary;
        }
    atomicStoreRelaxed(&forbid_fragment_pool_access, true);
    wthread_t threads[2];
    for (unsigned reader = 0; reader < 2; ++reader)
        require(threadCreate(&threads[reader], offerSharedFragments, &probes[reader]) == kWThreadErrorNone,
                "failed to start shared fragment reader");
    for (unsigned reader = 0; reader < 2; ++reader)
        require(threadJoin(threads[reader]) == 0, "failed to join shared fragment reader");
    require(atomicLoadRelaxed(&completed) == kSharedFragmentDatagrams && table->retained_bytes == 0,
            "shared readers lost datagrams or leaked assembly charges");

    unsigned accepted = 0;
    for (unsigned i = 0; i < kDeviceFragAffinityMaxEntries; ++i)
    {
        sbuf_t                             *buf = makeFragment(3000 + i, 8000, false);
        device_frag_affinity_result_t       result;
        const device_frag_affinity_action_t action =
            deviceFragAffinityOffer(table, sbufGetRawPtr(buf), sbufGetLength(buf), buf, &result);
        accepted += action == kDeviceFragAffinityStaged;
        require(table->retained_bytes <= kDeviceFragAffinityMaxAssemblyBytes,
                "shared fragment readers exceeded the single device assembly budget");
    }
    require(accepted > 0 && accepted < kDeviceFragAffinityMaxEntries,
            "shared assembly allocation budget was not enforced");
    deviceFragAffinityEndGeneration(table);
    deviceFragAffinityRetireReleasePool(table);
    require(table->retained_bytes == 0, "shared retirement leaked detached allocations");
    deviceFragAffinityDestroy(table);
    atomicStoreRelaxed(&forbid_fragment_pool_access, false);
}

static void testSharedRawResultsSurviveOtherReaders(void)
{
    device_frag_affinity_table_t *table = deviceFragAffinityCreate(g_pool, kDeviceFragmentPreserve);
    deviceFragAffinityEnableShared(table, 64);
    sbuf_t                       *tails[2] = {makeFragment(4000, 8, false), makeFragment(4001, 8, false)};
    sbuf_t                       *zeros[2] = {makeFragment(4000, 0, true), makeFragment(4001, 0, true)};
    device_frag_affinity_result_t results[2];
    atomicStoreRelaxed(&forbid_fragment_pool_access, true);
    for (unsigned i = 0; i < 2; ++i)
    {
        require(
            deviceFragAffinityOffer(table, sbufGetRawPtr(tails[i]), sbufGetLength(tails[i]), tails[i], &results[i]) ==
                kDeviceFragAffinityStaged,
            "shared raw tail was not staged");
        require(
            deviceFragAffinityOffer(table, sbufGetRawPtr(zeros[i]), sbufGetLength(zeros[i]), zeros[i], &results[i]) ==
                kDeviceFragAffinityDispatch,
            "shared raw zero did not release its tail");
    }
    for (unsigned i = 0; i < 2; ++i)
    {
        require(results[i].released_count == 1 && results[i].released[0] == tails[i],
                "another reader clobbered caller-owned raw release storage");
        sbufDestroy(results[i].released[0]);
        sbufDestroy(zeros[i]);
    }
    require(table->retained_bytes == 0 && table->staged_total == 0, "raw shared dispatch leaked staging charges");
    deviceFragAffinityDestroy(table);
    atomicStoreRelaxed(&forbid_fragment_pool_access, false);
}

int main(void)
{
    testCaseSet("device_frag_affinity_test");
    g_large_master = masterpoolCreateWithCapacity(16);
    g_small_master = masterpoolCreateWithCapacity(16);
    g_medium_master = masterpoolCreateWithCapacity(16);
    g_splice_master = masterpoolCreateWithCapacity(16);
    require(g_large_master != NULL && g_small_master != NULL, "failed to create master pools");

    g_pool = bufferpoolCreate(g_large_master, g_medium_master, g_small_master, 8, 65536, 32768, 4096, 65536, 65536);
    require(g_pool != NULL, "failed to create the buffer pool");

    GSTATE.workers_count = 4;
    bufferpoolUpdateAllocationPaddings(g_pool, 64, 64, 64, 64);
    testCompletion();
    testTrustedHeaderChecksum();
    testRejectionAndRetirement();
    testBounds();
    testRaw();
    testWholeFingerprintAndWorkerAreIndependent();
    testIsolationAndGrowthPeak();
    testSharedReadersAndGlobalBudget();
    testSharedRawResultsSurviveOtherReaders();

    bufferpoolDestroy(g_pool);
    masterpoolMakeEmpty(g_large_master);
    masterpoolMakeEmpty(g_small_master);
    masterpoolMakeEmpty(g_medium_master);
    masterpoolMakeEmpty(g_splice_master);
    masterpoolDestroy(g_large_master);
    masterpoolDestroy(g_small_master);
    masterpoolDestroy(g_medium_master);
    masterpoolDestroy(g_splice_master);
    puts("Device fragment affinity tests passed");
    return 0;
}
