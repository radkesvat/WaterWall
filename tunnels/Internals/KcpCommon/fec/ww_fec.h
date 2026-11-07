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
        kKcpFecOuterHeaderSize = 8
    };

    typedef bool (*kcp_fec_emit_fn)(void *ctx, const uint8_t *packet, size_t packet_len);

    typedef struct kcp_fec_encoder_s kcp_fec_encoder_t;
    typedef struct kcp_fec_decoder_s kcp_fec_decoder_t;

    kcp_fec_encoder_t *kcpFecEncoderCreate(uint8_t data_shards, uint8_t parity_shards);
    void               kcpFecEncoderDestroy(kcp_fec_encoder_t **encoder_ptr);
    /* Discard a partial parity block while preserving monotonically advancing shard identity. */
    void kcpFecEncoderDiscardPending(kcp_fec_encoder_t *encoder);
    bool kcpFecEncodePacket(kcp_fec_encoder_t *encoder, const uint8_t *packet, size_t packet_len, kcp_fec_emit_fn emit,
                            void *ctx);

    kcp_fec_decoder_t *kcpFecDecoderCreate(uint8_t data_shards, uint8_t parity_shards);
    void               kcpFecDecoderDestroy(kcp_fec_decoder_t **decoder_ptr);
    bool kcpFecDecodePacket(kcp_fec_decoder_t *decoder, const uint8_t *packet, size_t packet_len, kcp_fec_emit_fn emit,
                            void *ctx);

#ifdef __cplusplus
}
#endif
