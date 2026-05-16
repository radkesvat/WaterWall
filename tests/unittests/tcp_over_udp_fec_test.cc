#include "ww_fec.h"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <set>
#include <string>
#include <vector>

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

void require(bool condition, const char *message)
{
    if (! condition)
    {
        std::cerr << message << '\n';
        std::exit(1);
    }
}

// Proves that a 3+2 FEC block can recover all original data when one data shard
// is missing but enough parity remains.
void testRecoveryWithOneMissingDataShard()
{
    tcpoverudp_fec_encoder_t *encoder = tcpoverudpFecEncoderCreate(3, 2);
    tcpoverudp_fec_decoder_t *decoder = tcpoverudpFecDecoderCreate(3, 2);
    require(encoder != nullptr && decoder != nullptr, "failed to create FEC encoder/decoder");

    std::vector<Bytes> payloads = {
        bytesFromString("alpha"),
        bytesFromString("bravo has a longer payload"),
        bytesFromString("charlie"),
    };

    EmitCollector encoded;
    for (const Bytes &payload : payloads)
    {
        require(tcpoverudpFecEncodePacket(encoder, payload.data(), payload.size(), collectPacket, &encoded),
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
        require(tcpoverudpFecDecodePacket(decoder, packet.data(), packet.size(), collectPacket, &decoded),
                "FEC decode failed unexpectedly");
    }

    std::multiset<Bytes> expected(payloads.begin(), payloads.end());
    std::multiset<Bytes> actual(decoded.packets.begin(), decoded.packets.end());
    require(actual == expected, "FEC did not recover the missing data shard");

    tcpoverudpFecEncoderDestroy(&encoder);
    tcpoverudpFecDecoderDestroy(&decoder);
}

// Proves that a failed parity callback does not leave the encoder stuck in a
// partially emitted block.
void testEncoderRecoversAfterFailedParityEmit()
{
    tcpoverudp_fec_encoder_t *encoder = tcpoverudpFecEncoderCreate(2, 1);
    require(encoder != nullptr, "failed to create FEC encoder");

    EmitCollector first_block;
    first_block.fail_at = 3;

    Bytes first  = bytesFromString("first");
    Bytes second = bytesFromString("second");
    require(tcpoverudpFecEncodePacket(encoder, first.data(), first.size(), collectPacket, &first_block),
            "first FEC packet failed unexpectedly");
    require(! tcpoverudpFecEncodePacket(encoder, second.data(), second.size(), collectPacket, &first_block),
            "expected parity emit failure");
    require(first_block.packets.size() == 2, "failed parity emit should keep the two data packets only");

    EmitCollector second_block;
    Bytes          third  = bytesFromString("third");
    Bytes          fourth = bytesFromString("fourth");
    require(tcpoverudpFecEncodePacket(encoder, third.data(), third.size(), collectPacket, &second_block),
            "encoder did not accept data after a failed parity emit");
    require(tcpoverudpFecEncodePacket(encoder, fourth.data(), fourth.size(), collectPacket, &second_block),
            "encoder did not finish a new block after a failed parity emit");
    require(second_block.packets.size() == 3, "encoder did not reset to a fresh 2+1 FEC block");

    tcpoverudpFecEncoderDestroy(&encoder);
}

// Proves that the decoder rejects malformed packets before they can affect
// decoder state or emit payloads.
void testInvalidPacketsAreRejected()
{
    tcpoverudp_fec_decoder_t *decoder = tcpoverudpFecDecoderCreate(2, 1);
    require(decoder != nullptr, "failed to create FEC decoder");

    EmitCollector decoded;
    uint8_t       tiny_packet[1] = {0};
    require(! tcpoverudpFecDecodePacket(decoder, tiny_packet, sizeof(tiny_packet), collectPacket, &decoded),
            "tiny FEC packet was accepted");

    uint8_t unknown_flag_packet[kTcpOverUdpFecOuterHeaderSize] = {0};
    require(! tcpoverudpFecDecodePacket(decoder, unknown_flag_packet, sizeof(unknown_flag_packet), collectPacket,
                                        &decoded),
            "unknown FEC packet flag was accepted");

    tcpoverudpFecDecoderDestroy(&decoder);
}

} // namespace

int main()
{
    testRecoveryWithOneMissingDataShard();
    testEncoderRecoversAfterFailedParityEmit();
    testInvalidPacketsAreRejected();
    return 0;
}
