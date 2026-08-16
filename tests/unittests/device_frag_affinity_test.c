#include "devices/device_frag_affinity.h"
#include "wwapi.h"

static master_pool_t *g_large_master;
static master_pool_t *g_small_master;
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

static device_frag_affinity_result_t offerDispatch(device_frag_affinity_table_t *table, sbuf_t *buf,
                                                   const char *message)
{
    device_frag_affinity_result_t       result;
    const device_frag_affinity_action_t action =
        deviceFragAffinityOffer(table, sbufGetRawPtr(buf), sbufGetLength(buf), buf, &result);
    require(action == kDeviceFragAffinityDispatch, message);
    require(result.publication.valid, "a dispatched fragment had no settlement token");
    return result;
}

static void completeDatagram(device_frag_affinity_table_t *table, uint16_t identification,
                             device_frag_settlement_t terminal_settlement)
{
    sbuf_t                       *zero        = makeFragment(identification, 0, true);
    device_frag_affinity_result_t zero_result = offerDispatch(table, zero, "fragment zero was not dispatched");
    deviceFragAffinitySettlePublication(table, &zero_result.publication, kDeviceFragSettlementResiduePresent);
    bufferpoolReuseBuffer(g_pool, zero);

    sbuf_t                       *tail        = makeFragment(identification, 8, false);
    device_frag_affinity_result_t tail_result = offerDispatch(table, tail, "fragment tail was not dispatched");
    deviceFragAffinitySettlePublication(table, &tail_result.publication, terminal_settlement);
    bufferpoolReuseBuffer(g_pool, tail);
}

static void testSettlementControlsSameIdentityReuse(void)
{
    device_frag_affinity_table_t *table = deviceFragAffinityCreate(g_pool);
    require(table != NULL, "failed to create the fragment table");

    completeDatagram(table, 13300, kDeviceFragSettlementUnknown);
    sbuf_t                       *unknown_retry = makeFragment(13300, 8, false);
    device_frag_affinity_result_t ignored;
    require(deviceFragAffinityOffer(
                table, sbufGetRawPtr(unknown_retry), sbufGetLength(unknown_retry), unknown_retry, &ignored) ==
                kDeviceFragAffinityConsumedDrop,
            "an unknown-residue identity was reused immediately");

    completeDatagram(table, 13301, kDeviceFragSettlementNoResidue);
    sbuf_t *clean_retry = makeFragment(13301, 8, false);
    require(
        deviceFragAffinityOffer(table, sbufGetRawPtr(clean_retry), sbufGetLength(clean_retry), clean_retry, &ignored) ==
            kDeviceFragAffinityStaged,
        "a proven-clean identity was not reusable");

    deviceFragAffinityDestroy(table);
}

int main(void)
{
    g_large_master = masterpoolCreateWithCapacity(16);
    g_small_master = masterpoolCreateWithCapacity(16);
    require(g_large_master != NULL && g_small_master != NULL, "failed to create master pools");

    g_pool = bufferpoolCreate(g_large_master, g_small_master, 8, 512, 256);
    require(g_pool != NULL, "failed to create the buffer pool");

    testSettlementControlsSameIdentityReuse();

    bufferpoolDestroy(g_pool);
    masterpoolMakeEmpty(g_large_master);
    masterpoolMakeEmpty(g_small_master);
    masterpoolDestroy(g_large_master);
    masterpoolDestroy(g_small_master);
    puts("Device fragment affinity tests passed");
    return 0;
}
