#pragma once

#include <stddef.h>
#include <stdint.h>

#define CHACHA20_BLOCK_SIZE      (64)
#define CHACHA20_KEY_SIZE        (32)
#define CHACHA20_IETF_NONCE_SIZE (12)

struct chacha20_ctx
{
    uint32_t state[16];
};

/* Initialize an RFC 8439 ChaCha20 stream at block counter zero. */
void chacha20_init_ietf(struct chacha20_ctx *ctx, const uint8_t key[CHACHA20_KEY_SIZE],
                        const uint8_t nonce[CHACHA20_IETF_NONCE_SIZE]);

/*
 * Generate one 64-byte keystream block and advance the 32-bit block counter.
 * The caller must change the nonce before requesting a block after counter
 * UINT32_MAX; this primitive deliberately does not own nonce allocation.
 */
void chacha20_keystream_block(struct chacha20_ctx *ctx, uint8_t out[CHACHA20_BLOCK_SIZE]);
