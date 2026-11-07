/*
 * Covers: Verifies the KCP Reed-Solomon FEC helper directly, including one missing data shard
 * recovery, encoder reset after a failed parity emit callback, and malformed packet rejection.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Checks: Assertion labels include: FEC encode failed unexpectedly; expected 3 data shards and 2 parity
 * shards; FEC decode failed unexpectedly; FEC did not recover the missing data shard
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.kcp_fec_unit
 */
#include "ww_fec.h"
#include "ww_fec_allocator.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <set>
#include <string>
#include <vector>

#if defined(WW_FEC_ALLOCATOR_TEST)
#include <sys/wait.h>
#include <unistd.h>

static bool        refuse_allocations;
static std::size_t allocation_calls;
static std::size_t free_calls;

extern "C" void *__real_mi_malloc(std::size_t size);
extern "C" void  __real_mi_free(void *ptr);

extern "C" void *__wrap_mi_malloc(std::size_t size)
{
    ++allocation_calls;
    return refuse_allocations ? nullptr : __real_mi_malloc(size);
}

extern "C" void __wrap_mi_free(void *ptr)
{
    if (ptr != nullptr)
        ++free_calls;
    __real_mi_free(ptr);
}
#endif

namespace
{

using Bytes = std::vector<uint8_t>;

// Captures packets emitted by the FEC API and can inject one deterministic
// callback failure to exercise encoder recovery behavior.
struct EmitCollector
{
    std::vector<Bytes> packets;
    size_t             calls   = 0;
    size_t             fail_at = 0;
};

bool collectPacket(void *ctx, const uint8_t *packet, size_t packet_len)
{
    auto *collector = static_cast<EmitCollector *>(ctx);
    collector->calls += 1;

    if (collector->fail_at != 0 && collector->calls == collector->fail_at)
    {
        return false;
    }

    collector->packets.emplace_back(packet, packet + packet_len);
    return true;
}

// Keeps the test vectors readable while still passing raw byte buffers into the
// C-facing FEC API.
Bytes bytesFromString(const char *text)
{
    return Bytes(text, text + std::char_traits<char>::length(text));
}


// Proves that a 3+2 FEC block can recover all original data when one data shard
// is missing but enough parity remains.
void testRecoveryWithOneMissingDataShard()
{
    kcp_fec_encoder_t *encoder = kcpFecEncoderCreate(3, 2);
    kcp_fec_decoder_t *decoder = kcpFecDecoderCreate(3, 2);
    require(encoder != nullptr && decoder != nullptr, "failed to create FEC encoder/decoder");

    std::vector<Bytes> payloads = {
        bytesFromString("alpha"),
        bytesFromString("bravo has a longer payload"),
        bytesFromString("charlie"),
    };

    EmitCollector encoded;
    for (const Bytes &payload : payloads)
    {
        require(kcpFecEncodePacket(encoder, payload.data(), payload.size(), collectPacket, &encoded),
                "FEC encode failed unexpectedly");
    }
    require(encoded.packets.size() == 5, "expected 3 data shards and 2 parity shards");

    EmitCollector decoded;
    for (size_t i = 0; i < encoded.packets.size(); ++i)
    {
        if (i == 1)
        {
            continue;
        }

        const Bytes &packet = encoded.packets[i];
        require(kcpFecDecodePacket(decoder, packet.data(), packet.size(), collectPacket, &decoded),
                "FEC decode failed unexpectedly");
    }

    std::multiset<Bytes> expected(payloads.begin(), payloads.end());
    std::multiset<Bytes> actual(decoded.packets.begin(), decoded.packets.end());
    require(actual == expected, "FEC did not recover the missing data shard");

    kcpFecEncoderDestroy(&encoder);
    kcpFecDecoderDestroy(&decoder);
}

// Proves that a failed parity callback does not leave the encoder stuck in a
// partially emitted block.
void testEncoderRecoversAfterFailedParityEmit()
{
    kcp_fec_encoder_t *encoder = kcpFecEncoderCreate(2, 1);
    require(encoder != nullptr, "failed to create FEC encoder");

    EmitCollector first_block;
    first_block.fail_at = 3;

    Bytes first  = bytesFromString("first");
    Bytes second = bytesFromString("second");
    require(kcpFecEncodePacket(encoder, first.data(), first.size(), collectPacket, &first_block),
            "first FEC packet failed unexpectedly");
    require(! kcpFecEncodePacket(encoder, second.data(), second.size(), collectPacket, &first_block),
            "expected parity emit failure");
    require(first_block.packets.size() == 2, "failed parity emit should keep the two data packets only");

    EmitCollector second_block;
    Bytes          third  = bytesFromString("third");
    Bytes          fourth = bytesFromString("fourth");
    require(kcpFecEncodePacket(encoder, third.data(), third.size(), collectPacket, &second_block),
            "encoder did not accept data after a failed parity emit");
    require(kcpFecEncodePacket(encoder, fourth.data(), fourth.size(), collectPacket, &second_block),
            "encoder did not finish a new block after a failed parity emit");
    require(second_block.packets.size() == 3, "encoder did not reset to a fresh 2+1 FEC block");

    kcpFecEncoderDestroy(&encoder);
}

// Proves that the decoder rejects malformed packets before they can affect
// decoder state or emit payloads.
void testInvalidPacketsAreRejected()
{
    kcp_fec_decoder_t *decoder = kcpFecDecoderCreate(2, 1);
    require(decoder != nullptr, "failed to create FEC decoder");

    EmitCollector decoded;
    uint8_t       tiny_packet[1] = {0};
    require(! kcpFecDecodePacket(decoder, tiny_packet, sizeof(tiny_packet), collectPacket, &decoded),
            "tiny FEC packet was accepted");

    uint8_t unknown_flag_packet[kKcpFecOuterHeaderSize] = {0};
    require(! kcpFecDecodePacket(decoder, unknown_flag_packet, sizeof(unknown_flag_packet), collectPacket, &decoded),
            "unknown FEC packet flag was accepted");

    kcpFecDecoderDestroy(&decoder);
}

void testInvalidGeometryIsRejected()
{
    require(kcpFecEncoderCreate(0, 1) == nullptr, "zero data shard count was accepted");
    require(kcpFecDecoderCreate(1, 0) == nullptr, "zero parity shard count was accepted");
    require(kcpFecEncoderCreate(200, 100) == nullptr, "oversized encoder shard count was accepted");
    require(kcpFecDecoderCreate(200, 100) == nullptr, "oversized decoder shard count was accepted");

    FecVector<uint64_t> values;
    try
    {
        values.resize(values.max_size() + 1);
        require(false, "unrepresentable FEC vector size was accepted");
    }
    catch (const std::length_error &)
    {
    }
}

#if defined(WW_FEC_ALLOCATOR_TEST)
void unexpectedExitCleanup()
{
    _Exit(72);
}

bool acceptPacket(void *, const uint8_t *, size_t)
{
    return true;
}

bool throwAllocationFailure(void *, const uint8_t *, size_t)
{
    throw std::bad_alloc();
}

void testFatalAllocation(unsigned kind)
{
    const pid_t child = fork();
    require(child >= 0, "failed to fork FEC allocation failure case");
    if (child == 0)
    {
        auto *encoder = kind >= 2 ? kcpFecEncoderCreate(2, 1) : nullptr;
        auto *decoder = kind == 3 ? kcpFecDecoderCreate(2, 1) : nullptr;
        if (atexit(unexpectedExitCleanup) != 0)
            _Exit(74);
        alarm(3);
        refuse_allocations = kind != 4;
        uint8_t packet[]   = {0, 0, 0, 0, 0xf1, 0, 3, 0, 'x'};
        switch (kind)
        {
        case 0:
            kcpFecEncoderCreate(2, 1);
            break;
        case 1:
            kcpFecDecoderCreate(2, 1);
            break;
        case 2:
            kcpFecEncodePacket(encoder, packet, sizeof(packet), acceptPacket, nullptr);
            break;
        case 3:
            kcpFecDecodePacket(decoder, packet, sizeof(packet), acceptPacket, nullptr);
            break;
        case 4:
            kcpFecEncodePacket(encoder, packet, sizeof(packet), throwAllocationFailure, nullptr);
            break;
        }
        _Exit(73);
    }
    int status = 0;
    require(waitpid(child, &status, 0) == child, "failed to wait for FEC allocation failure case");
    require(WIFEXITED(status) && WEXITSTATUS(status) == 1,
            "FEC allocation failure must exit immediately with status 1 without cleanup or recovery");
}
#endif

} // namespace

int main()
{
    testCaseSet("kcp_fec_test");
#if defined(WW_FEC_ALLOCATOR_TEST)
    const auto allocations_before = allocation_calls;
    const auto frees_before       = free_calls;
#endif
    testRecoveryWithOneMissingDataShard();
    testEncoderRecoversAfterFailedParityEmit();
    testInvalidPacketsAreRejected();
    testInvalidGeometryIsRejected();
#if defined(WW_FEC_ALLOCATOR_TEST)
    require(allocation_calls > allocations_before, "FEC did not use the WaterWall mimalloc backend");
    require(allocation_calls - allocations_before == free_calls - frees_before,
            "FEC retained heap storage after destruction or geometry rejection");
    for (unsigned kind = 0; kind < 5; ++kind)
        testFatalAllocation(kind);
#endif
    return 0;
}
