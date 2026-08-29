#include "structure.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void initTestKeypair(wireguard_keypair_t *keypair)
{
    memset(keypair, 0, sizeof(*keypair));
    for (size_t i = 0; i < WIREGUARD_SESSION_KEY_LEN; ++i)
    {
        keypair->sending_key[i]   = (uint8_t) (0x20U + i);
        keypair->receiving_key[i] = (uint8_t) (0x20U + i);
    }
    keypair->sending_counter = 0;
    keypair->sending_valid   = true;
    keypair->receiving_valid = true;
    keypair->valid           = true;
}

static void fillPattern(uint8_t *buf, size_t len, uint8_t seed)
{
    for (size_t i = 0; i < len; ++i)
    {
        buf[i] = (uint8_t) ((i * 37U + seed) & 0xFFU);
    }
}

static void testShortCiphertextRejected(buffer_pool_t *pool, wireguard_keypair_t *keypair)
{
    uint8_t dummy[WIREGUARD_AUTHTAG_LEN];
    memset(dummy, 0xAA, sizeof(dummy));

    // Lengths 0 to 15 (less than WIREGUARD_AUTHTAG_LEN)
    for (uint32_t len = 0; len < WIREGUARD_AUTHTAG_LEN; ++len)
    {
        sbuf_t *buf = wireguarddeviceDecryptTransportPayload(pool, dummy, len, 0, keypair);
        require(buf == NULL, "short ciphertext was not rejected");
    }
}

static void testKeepaliveSucceeds(buffer_pool_t *pool, wireguard_keypair_t *keypair)
{
    uint8_t  ct[WIREGUARD_AUTHTAG_LEN];
    uint64_t nonce = keypair->sending_counter;

    require(wireguardEncryptPacket(ct, sizeof(ct), NULL, 0, keypair), "failed to encrypt keepalive packet");

    sbuf_t *buf = wireguarddeviceDecryptTransportPayload(pool, ct, (uint32_t) sizeof(ct), nonce, keypair);
    require(buf != NULL, "keepalive packet decryption failed");
    require(sbufGetLength(buf) == 0, "keepalive packet returned non-zero length");
    bufferpoolReuseBuffer(pool, buf);
}

static void testPlaintextRoundtrip(buffer_pool_t *pool, wireguard_keypair_t *keypair, uint32_t plaintext_len,
                                   uint8_t seed, const char *label)
{
    uint8_t *pt = malloc(plaintext_len);
    require(pt != NULL, "failed to allocate test plaintext buffer");
    fillPattern(pt, plaintext_len, seed);

    uint32_t ciphertext_len = plaintext_len + WIREGUARD_AUTHTAG_LEN;
    uint8_t *ct             = malloc(ciphertext_len);
    require(ct != NULL, "failed to allocate test ciphertext buffer");

    uint64_t nonce = keypair->sending_counter;
    require(wireguardEncryptPacket(ct, ciphertext_len, pt, plaintext_len, keypair), "encryption failed");

    sbuf_t *buf = wireguarddeviceDecryptTransportPayload(pool, ct, ciphertext_len, nonce, keypair);
    require(buf != NULL, label);
    require(sbufGetLength(buf) == plaintext_len, "decrypted length mismatch");
    require(sbufGetMaximumWriteableSize(buf) >= plaintext_len, "buffer writable capacity is too small");
    require(sbufGetLeftPadding(buf) >= bufferpoolGetLargeBufferPadding(pool),
            "decryption buffer lacks the worker pool's required left padding");
    require(memcmp(sbufGetRawPtr(buf), pt, plaintext_len) == 0, "decrypted content mismatch");

    bufferpoolReuseBuffer(pool, buf);
    free(ct);
    free(pt);
}

static void testTamperedCiphertextRejected(buffer_pool_t *pool, wireguard_keypair_t *keypair)
{
    const uint32_t plaintext_len  = 4097;
    const uint32_t ciphertext_len = plaintext_len + WIREGUARD_AUTHTAG_LEN;

    uint8_t *pt = malloc(plaintext_len);
    uint8_t *ct = malloc(ciphertext_len);
    require(pt != NULL && ct != NULL, "failed to allocate buffers for tamper test");
    fillPattern(pt, plaintext_len, 0x77);

    uint64_t nonce = keypair->sending_counter;
    require(wireguardEncryptPacket(ct, ciphertext_len, pt, plaintext_len, keypair), "tamper test encryption failed");

    // Tamper with payload byte
    ct[20] ^= 0x01;
    sbuf_t *buf = wireguarddeviceDecryptTransportPayload(pool, ct, ciphertext_len, nonce, keypair);
    require(buf == NULL, "tampered ciphertext payload was accepted");

    // Restore and tamper with auth tag byte
    ct[20] ^= 0x01;
    ct[ciphertext_len - 1] ^= 0x80;
    buf = wireguarddeviceDecryptTransportPayload(pool, ct, ciphertext_len, nonce, keypair);
    require(buf == NULL, "tampered ciphertext auth tag was accepted");

    free(ct);
    free(pt);
}

int main(void)
{
    require(wCryptoGlobalInit() == kWCryptoOk, "wCryptoGlobalInit failed");
    require(wireguardInit() == kWCryptoOk, "wireguardInit failed");

    master_pool_t *large_master = masterpoolCreateWithCapacity(8);
    master_pool_t *small_master = masterpoolCreateWithCapacity(8);
    require(large_master != NULL && small_master != NULL, "failed to create master pools");

    // Standard small buffer: 4096, large buffer: 32768
    buffer_pool_t *pool = bufferpoolCreate(large_master, small_master, 8, 32768, 4096);
    require(pool != NULL, "failed to create buffer pool");
    bufferpoolUpdateAllocationPaddings(pool, 64, 64);

    wireguard_keypair_t keypair;
    initTestKeypair(&keypair);

    // 1. ciphertext shorter than authentication tag is rejected
    testShortCiphertextRejected(pool, &keypair);

    // 2. authenticated zero-length keepalive succeeds
    testKeepaliveSucceeds(pool, &keypair);

    // 3. ordinary ~1500-byte plaintext succeeds
    testPlaintextRoundtrip(pool, &keypair, 1500, 0x11, "1500-byte payload decryption failed");

    // 4. 4096-byte plaintext at small-tier boundary succeeds
    testPlaintextRoundtrip(pool, &keypair, 4096, 0x22, "4096-byte payload decryption failed");

    // 5. 4097-byte plaintext at overflow boundary succeeds with sufficient capacity
    testPlaintextRoundtrip(pool, &keypair, 4097, 0x33, "4097-byte payload decryption failed");

    // 6. a payload beyond both pool tiers keeps the chain's padding on its fallback buffer
    testPlaintextRoundtrip(pool, &keypair, 32769, 0x44, "32769-byte fallback payload decryption failed");

    // 7. tampered 4097-byte ciphertext is rejected
    testTamperedCiphertextRejected(pool, &keypair);

    bufferpoolDestroy(pool);
    masterpoolMakeEmpty(large_master);
    masterpoolMakeEmpty(small_master);
    masterpoolDestroy(large_master);
    masterpoolDestroy(small_master);

    wCryptoGlobalCleanup();
    return 0;
}
