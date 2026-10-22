/* Production stream carrier: every header/body split, byte-at-a-time input,
 * coalesced packets, maximum datagram, invalid length, allocation refusal and
 * partial-frame cleanup. Pure allocator fixture, checks survive NDEBUG.
 * CTest: waterwall.quic_carrier_unit in linux-unit-debug/linux-unit-release. */

#include "carrier.h"
#include "quic_engine.h"

#include "test_assert.h"

#include <stdlib.h>
#include <string.h>

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

typedef struct allocation_state
{
    size_t bytes;
    size_t allocations;
    bool   refuse;
} allocation_state_t;

static void *allocate(void *context, size_t length)
{
    allocation_state_t *state = context;
    if (state->refuse)
    {
        return NULL;
    }
    void *memory = malloc(length);
    require(memory != NULL, "fixture allocation failed");
    state->bytes += length;
    state->allocations++;
    return memory;
}

static void deallocate(void *context, void *memory, size_t length)
{
    allocation_state_t *state = context;
    require(state->bytes >= length && state->allocations > 0, "allocation was released twice");
    state->bytes -= length;
    state->allocations--;
    free(memory);
}

static ww_quic_carrier_t makeCarrier(allocation_state_t *state)
{
    return (ww_quic_carrier_t) {.context = state, .allocate = allocate, .deallocate = deallocate};
}

static void testEverySplit(void)
{
    uint8_t frame[4 + 263];
    ww_quic_carrier_header(frame, sizeof(frame) - 4);
    require(memcmp(frame, "\0\0\1\7", 4) == 0, "frame length is not network byte order");
    for (size_t i = 4; i < sizeof(frame); ++i)
    {
        frame[i] = (uint8_t) (i * 37);
    }
    for (size_t split = 0; split <= sizeof(frame); ++split)
    {
        allocation_state_t       state    = {0};
        ww_quic_carrier_t        carrier  = makeCarrier(&state);
        size_t                   consumed = SIZE_MAX, packet_length = SIZE_MAX;
        const uint8_t           *packet = NULL;
        ww_quic_carrier_result_t result =
            ww_quic_carrier_decode(&carrier, frame, split, &consumed, &packet, &packet_length);
        require(consumed == split, "prefix input was not consumed exactly");
        if (split < sizeof(frame))
        {
            require(result == WW_QUIC_CARRIER_MORE && packet == NULL && packet_length == 0,
                    "incomplete frame was exposed as a datagram");
            result = ww_quic_carrier_decode(
                &carrier, frame + split, sizeof(frame) - split, &consumed, &packet, &packet_length);
            require(consumed == sizeof(frame) - split, "suffix input was not consumed exactly");
        }
        require(result == WW_QUIC_CARRIER_PACKET && packet_length == sizeof(frame) - 4,
                "split frame did not complete once");
        require(memcmp(packet, frame + 4, packet_length) == 0, "split frame changed bytes");
        ww_quic_carrier_release_packet(&carrier);
        require(ww_quic_carrier_retained(&carrier) == 0, "released frame retained parser bytes");
        require(state.bytes == 0 && state.allocations == 0, "split frame leaked allocation");
        ww_quic_carrier_destroy(&carrier);
    }
}

static void testSingleBytesAndCoalescing(void)
{
    uint8_t frames[512 * 5];
    for (size_t i = 0; i < 512; ++i)
    {
        ww_quic_carrier_header(frames + i * 5, 1);
        frames[i * 5 + 4] = (uint8_t) i;
    }
    for (size_t stride = 1; stride <= sizeof(frames); stride = sizeof(frames))
    {
        allocation_state_t state   = {0};
        ww_quic_carrier_t  carrier = makeCarrier(&state);
        size_t             offset = 0, packets = 0;
        while (offset < sizeof(frames))
        {
            size_t available = sizeof(frames) - offset;
            if (available > stride)
            {
                available = stride;
            }
            size_t                   consumed = 0, length = 0;
            const uint8_t           *packet = NULL;
            ww_quic_carrier_result_t result =
                ww_quic_carrier_decode(&carrier, frames + offset, available, &consumed, &packet, &length);
            require(consumed > 0 && consumed <= available, "parser did not make bounded progress");
            offset += consumed;
            if (result == WW_QUIC_CARRIER_PACKET)
            {
                require(length == 1 && packet[0] == (uint8_t) packets, "coalescing changed datagram order");
                packets++;
                ww_quic_carrier_release_packet(&carrier);
            }
            else
            {
                require(result == WW_QUIC_CARRIER_MORE, "valid tiny datagrams were rejected");
            }
        }
        require(packets == 512, "parser lost or duplicated a coalesced datagram");
        ww_quic_carrier_destroy(&carrier);
        require(state.bytes == 0 && state.allocations == 0, "coalesced datagrams leaked memory");
        if (stride == sizeof(frames))
        {
            break;
        }
    }
}

static void testMaximumAndTerminalInput(void)
{
    uint8_t *frame = malloc(4 + WW_QUIC_MAX_DATAGRAM);
    require(frame != NULL, "maximum datagram fixture allocation failed");
    memset(frame + 4, 0xA5, WW_QUIC_MAX_DATAGRAM);
    ww_quic_carrier_header(frame, WW_QUIC_MAX_DATAGRAM);
    allocation_state_t state    = {0};
    ww_quic_carrier_t  carrier  = makeCarrier(&state);
    size_t             consumed = 0, length = 0;
    const uint8_t     *packet = NULL;
    require(ww_quic_carrier_decode(&carrier, frame, 5, &consumed, &packet, &length) == WW_QUIC_CARRIER_MORE,
            "maximum frame prefix was rejected");
    require(state.bytes == WW_QUIC_MAX_DATAGRAM, "partial frame allocation is not bounded to declared length");
    require(ww_quic_carrier_decode(&carrier, frame + 5, WW_QUIC_MAX_DATAGRAM - 1, &consumed, &packet, &length) ==
                WW_QUIC_CARRIER_PACKET,
            "maximum datagram was rejected");
    require(length == WW_QUIC_MAX_DATAGRAM && memcmp(packet, frame + 4, length) == 0, "maximum datagram bytes changed");
    ww_quic_carrier_release_packet(&carrier);
    free(frame);

    const uint8_t invalid[][4] = {{0, 0, 0, 0}, {0, 0, 0x05, 0xC1}, {0xFF, 0xFF, 0xFF, 0xFF}};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        require(ww_quic_carrier_decode(&carrier, invalid[i], 4, &consumed, &packet, &length) == WW_QUIC_CARRIER_INVALID,
                "zero or oversized length was accepted");
        require(consumed == 4 && state.bytes == 0, "invalid length allocated or consumed body bytes");
        ww_quic_carrier_destroy(&carrier);
    }
    const uint8_t partial[] = {0, 0, 0, 3, 'a'};
    state.refuse            = true;
    require(ww_quic_carrier_decode(&carrier, partial, sizeof(partial), &consumed, &packet, &length) ==
                WW_QUIC_CARRIER_REFUSED,
            "allocation budget refusal was ignored");
    require(consumed == 4 && state.bytes == 0, "refusal consumed unadmitted body bytes");
    ww_quic_carrier_destroy(&carrier);
    state.refuse = false;
    require(ww_quic_carrier_decode(&carrier, partial, sizeof(partial), &consumed, &packet, &length) ==
                WW_QUIC_CARRIER_MORE,
            "partial body did not wait for remaining input");
    require(state.bytes == 3, "partial body was not accounted");
    ww_quic_carrier_destroy(&carrier);
    require(state.bytes == 0 && state.allocations == 0, "partial-frame EOF cleanup leaked memory");
}

int main(void)
{
    TEST_RUN_CASE(testEverySplit);
    TEST_RUN_CASE(testSingleBytesAndCoalescing);
    TEST_RUN_CASE(testMaximumAndTerminalInput);
    return 0;
}
