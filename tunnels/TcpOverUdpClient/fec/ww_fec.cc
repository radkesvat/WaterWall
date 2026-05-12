#include "ww_fec.h"

#include "fec.h"
#include "encoding.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <new>
#include <vector>

struct tcpoverudp_fec_encoder_s
{
    FEC                  fec;
    std::vector<row_type> shards;
    size_t               pkt_idx;
    size_t               data_shards;
    size_t               parity_shards;
};

struct tcpoverudp_fec_decoder_s
{
    FEC fec;
};

static void tcpoverudpFecEncoderResetBlock(tcpoverudp_fec_encoder_t *encoder)
{
    for (row_type &shard : encoder->shards)
    {
        shard.reset();
    }
    encoder->pkt_idx = 0;
}

static void tcpoverudpFecEncoderSkipParity(tcpoverudp_fec_encoder_t *encoder, size_t first_parity_index)
{
    byte dummy[fecHeaderSize] = {};

    for (size_t i = first_parity_index; i < encoder->data_shards + encoder->parity_shards; ++i)
    {
        encoder->fec.MarkFEC(dummy);
    }
}

static inline int tcpoverudpFecRxLimit(uint8_t data_shards, uint8_t parity_shards)
{
    return (int) (3U * (uint32_t) (data_shards + parity_shards));
}

static bool tcpoverudpFecEmitRecoveredShard(const row_type &shard, tcpoverudp_fec_emit_fn emit, void *ctx)
{
    if (shard == nullptr || shard->size() < 2)
    {
        return false;
    }

    uint16_t shard_size = 0;
    decode16u((byte *) shard->data(), &shard_size);

    if (shard_size < 2 || (size_t) shard_size > shard->size())
    {
        return false;
    }

    return emit(ctx, shard->data() + 2, shard_size - 2);
}

extern "C" tcpoverudp_fec_encoder_t *tcpoverudpFecEncoderCreate(uint8_t data_shards, uint8_t parity_shards)
{
    if (data_shards == 0 || parity_shards == 0)
    {
        return nullptr;
    }

    try
    {
        tcpoverudp_fec_encoder_t *encoder = new (std::nothrow) tcpoverudp_fec_encoder_t;
        if (encoder == nullptr)
        {
            return nullptr;
        }

        encoder->fec           = FEC::New(tcpoverudpFecRxLimit(data_shards, parity_shards), data_shards, parity_shards);
        encoder->data_shards   = data_shards;
        encoder->parity_shards = parity_shards;
        encoder->pkt_idx       = 0;
        encoder->shards.resize((size_t) (data_shards + parity_shards), nullptr);

        return encoder;
    }
    catch (...)
    {
        return nullptr;
    }
}

extern "C" void tcpoverudpFecEncoderDestroy(tcpoverudp_fec_encoder_t **encoder_ptr)
{
    if (encoder_ptr == nullptr || *encoder_ptr == nullptr)
    {
        return;
    }

    delete *encoder_ptr;
    *encoder_ptr = nullptr;
}

extern "C" bool tcpoverudpFecEncodePacket(tcpoverudp_fec_encoder_t *encoder, const uint8_t *packet, size_t packet_len,
                                          tcpoverudp_fec_emit_fn emit, void *ctx)
{
    if (encoder == nullptr || packet == nullptr || packet_len == 0 || emit == nullptr)
    {
        return false;
    }

    if (packet_len > (size_t) (std::numeric_limits<uint16_t>::max() - 2U))
    {
        return false;
    }

    bool   block_ready       = false;
    size_t next_parity_index = encoder->data_shards;

    try
    {
        const size_t shard_len = packet_len + 2U;
        row_type     shard     = std::make_shared<std::vector<byte>>(shard_len);
        encode16u(shard->data(), (uint16_t) shard_len);
        std::copy_n(packet, packet_len, shard->data() + 2);

        std::vector<byte> data_packet(fecHeaderSize + shard_len);
        std::copy_n(shard->data(), shard_len, data_packet.data() + fecHeaderSize);
        encoder->fec.MarkData(data_packet.data(), (uint16_t) packet_len);
        encoder->shards[encoder->pkt_idx] = shard;

        encoder->pkt_idx += 1;
        bool emit_ok = emit(ctx, data_packet.data(), data_packet.size());

        if (encoder->pkt_idx != encoder->data_shards)
        {
            return emit_ok;
        }

        block_ready = true;
        encoder->fec.Encode(encoder->shards);

        for (size_t i = encoder->data_shards; i < encoder->data_shards + encoder->parity_shards; ++i)
        {
            next_parity_index = i;

            if (encoder->shards[i] == nullptr)
            {
                tcpoverudpFecEncoderSkipParity(encoder, next_parity_index);
                tcpoverudpFecEncoderResetBlock(encoder);
                return false;
            }

            std::vector<byte> parity_packet(fecHeaderSize + encoder->shards[i]->size());
            std::copy_n(encoder->shards[i]->data(), encoder->shards[i]->size(), parity_packet.data() + fecHeaderSize);
            encoder->fec.MarkFEC(parity_packet.data());
            next_parity_index = i + 1;

            if (! emit(ctx, parity_packet.data(), parity_packet.size()))
            {
                emit_ok = false;
            }
        }

        tcpoverudpFecEncoderResetBlock(encoder);

        return emit_ok;
    }
    catch (...)
    {
        if (block_ready || encoder->pkt_idx == encoder->data_shards)
        {
            tcpoverudpFecEncoderSkipParity(encoder, next_parity_index);
            tcpoverudpFecEncoderResetBlock(encoder);
        }
        return false;
    }
}

extern "C" tcpoverudp_fec_decoder_t *tcpoverudpFecDecoderCreate(uint8_t data_shards, uint8_t parity_shards)
{
    if (data_shards == 0 || parity_shards == 0)
    {
        return nullptr;
    }

    try
    {
        tcpoverudp_fec_decoder_t *decoder = new (std::nothrow) tcpoverudp_fec_decoder_t;
        if (decoder == nullptr)
        {
            return nullptr;
        }

        decoder->fec = FEC::New(tcpoverudpFecRxLimit(data_shards, parity_shards), data_shards, parity_shards);
        return decoder;
    }
    catch (...)
    {
        return nullptr;
    }
}

extern "C" void tcpoverudpFecDecoderDestroy(tcpoverudp_fec_decoder_t **decoder_ptr)
{
    if (decoder_ptr == nullptr || *decoder_ptr == nullptr)
    {
        return;
    }

    delete *decoder_ptr;
    *decoder_ptr = nullptr;
}

extern "C" bool tcpoverudpFecDecodePacket(tcpoverudp_fec_decoder_t *decoder, const uint8_t *packet, size_t packet_len,
                                          tcpoverudp_fec_emit_fn emit, void *ctx)
{
    if (decoder == nullptr || packet == nullptr || packet_len < fecHeaderSize || emit == nullptr)
    {
        return false;
    }

    try
    {
        std::vector<byte> packet_copy(packet, packet + packet_len);
        fecPacket         decoded = FEC::Decode(packet_copy.data(), packet_copy.size());

        if (decoded.flag != typeData && decoded.flag != typeFEC)
        {
            return false;
        }

        if (decoded.flag == typeData)
        {
            if (! tcpoverudpFecEmitRecoveredShard(decoded.data, emit, ctx))
            {
                return false;
            }
        }

        std::vector<row_type> recovered = decoder->fec.Input(decoded);
        for (const row_type &shard : recovered)
        {
            if (! tcpoverudpFecEmitRecoveredShard(shard, emit, ctx))
            {
                return false;
            }
        }

        return true;
    }
    catch (...)
    {
        return false;
    }
}
