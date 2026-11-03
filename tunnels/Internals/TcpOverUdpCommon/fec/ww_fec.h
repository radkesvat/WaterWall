#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    enum
    {
        kTcpOverUdpFecOuterHeaderSize = 8
    };

    typedef bool (*tcpoverudp_fec_emit_fn)(void *ctx, const uint8_t *packet, size_t packet_len);

    typedef struct tcpoverudp_fec_encoder_s tcpoverudp_fec_encoder_t;
    typedef struct tcpoverudp_fec_decoder_s tcpoverudp_fec_decoder_t;

    tcpoverudp_fec_encoder_t *tcpoverudpFecEncoderCreate(uint8_t data_shards, uint8_t parity_shards);
    void                      tcpoverudpFecEncoderDestroy(tcpoverudp_fec_encoder_t **encoder_ptr);
    /* Discard a partial parity block while preserving monotonically advancing shard identity. */
    void tcpoverudpFecEncoderDiscardPending(tcpoverudp_fec_encoder_t *encoder);
    bool tcpoverudpFecEncodePacket(tcpoverudp_fec_encoder_t *encoder, const uint8_t *packet, size_t packet_len,
                                   tcpoverudp_fec_emit_fn emit, void *ctx);

    tcpoverudp_fec_decoder_t *tcpoverudpFecDecoderCreate(uint8_t data_shards, uint8_t parity_shards);
    void                      tcpoverudpFecDecoderDestroy(tcpoverudp_fec_decoder_t **decoder_ptr);
    bool tcpoverudpFecDecodePacket(tcpoverudp_fec_decoder_t *decoder, const uint8_t *packet, size_t packet_len,
                                   tcpoverudp_fec_emit_fn emit, void *ctx);

#ifdef __cplusplus
}
#endif
