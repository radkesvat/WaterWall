#include "devices/device_frag_affinity.c"
#include "devices/device_frag_affinity.h"
#include "wwapi.h"

static master_pool_t *g_large_master;
static master_pool_t *g_small_master;
static master_pool_t *g_medium_master;
static master_pool_t *g_splice_master;
static buffer_pool_t *g_pool;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "device_frag_affinity_test: %s\n", message);
        exit(1);
    }
}

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
    device_frag_parse_result_t parsed = deviceFragAffinityParse(sbufGetRawPtr(buf), sbufGetLength(buf), &view);
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
        uint64_t hash;
        require(deviceFlowAffinityHash(sbufGetRawPtr(result.completed), 148, &hash), "complete hash failed");
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

int main(void)
{
    g_large_master = masterpoolCreateWithCapacity(16);
    g_small_master = masterpoolCreateWithCapacity(16);
    g_medium_master = masterpoolCreateWithCapacity(16);
    g_splice_master = masterpoolCreateWithCapacity(16);
    require(g_large_master != NULL && g_small_master != NULL, "failed to create master pools");

    g_pool = bufferpoolCreate(
        g_large_master, g_medium_master, g_small_master, g_splice_master, 8, 65536, 32768, 4096, 65536, 65536);
    require(g_pool != NULL, "failed to create the buffer pool");

    GSTATE.workers_count = 5;
    bufferpoolUpdateAllocationPaddings(g_pool, 64, 64, 64, 64);
    testCompletion();
    testRejectionAndRetirement();
    testBounds();
    testRaw();
    testIsolationAndGrowthPeak();

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
