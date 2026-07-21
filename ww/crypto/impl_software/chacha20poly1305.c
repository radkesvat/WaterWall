/* RFC 8439 ChaCha20-Poly1305 and XChaCha20-Poly1305. */

#include "private/crypto_backends.h"
#include "private/crypto_validation.h"
#include "private/defs.h"

#define POLY1305_KEY_SIZE 32
#define POLY1305_MAC_SIZE WCRYPTO_AEAD_TAG_SIZE

static const uint8_t zero[CHACHA20_BLOCK_SIZE] = {0};

static void generatePoly1305Key(struct poly1305_context *poly1305_state, struct chacha20_ctx *chacha20_state,
                                const uint8_t key[CHACHA20_KEY_SIZE], const uint8_t nonce[CHACHA20_IETF_NONCE_SIZE])
{
    uint8_t block[POLY1305_KEY_SIZE] = {0};
    chacha20_init_ietf(chacha20_state, key, nonce);
    chacha20(chacha20_state, block, block, sizeof(block));
    wCryptoSoftwarePoly1305Init(poly1305_state, block);
    wCryptoZero(block, sizeof(block));
}

static void calculateMac(uint8_t mac[POLY1305_MAC_SIZE], struct poly1305_context *poly1305_state,
                         const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *ad, size_t ad_len)
{
    uint8_t length_block[8] = {0};
    size_t  padded_len      = (ad_len + 15U) & ~(size_t) 15U;

    wCryptoSoftwarePoly1305Update(poly1305_state, ad, ad_len);
    wCryptoSoftwarePoly1305Update(poly1305_state, zero, padded_len - ad_len);
    wCryptoSoftwarePoly1305Update(poly1305_state, ciphertext, ciphertext_len);
    padded_len = (ciphertext_len + 15U) & ~(size_t) 15U;
    wCryptoSoftwarePoly1305Update(poly1305_state, zero, padded_len - ciphertext_len);
    U64TO8_LITTLE(length_block, (uint64_t) ad_len);
    wCryptoSoftwarePoly1305Update(poly1305_state, length_block, sizeof(length_block));
    U64TO8_LITTLE(length_block, (uint64_t) ciphertext_len);
    wCryptoSoftwarePoly1305Update(poly1305_state, length_block, sizeof(length_block));
    wCryptoSoftwarePoly1305Finish(poly1305_state, mac);
}

wcrypto_status_t wCryptoSoftwareChacha20Poly1305Encrypt(unsigned char *dst, size_t dst_capacity,
                                                        const unsigned char *src, size_t src_len,
                                                        const unsigned char *ad, size_t ad_len,
                                                        const unsigned char nonce[WCRYPTO_CHACHA20POLY1305_NONCE_SIZE],
                                                        const unsigned char key[WCRYPTO_CHACHA20POLY1305_KEY_SIZE])
{
    size_t           output_len = 0;
    wcrypto_status_t status =
        wCryptoValidateAeadEncrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key, &output_len);
    if (status != kWCryptoOk)
    {
        wCryptoZero(dst, output_len);
        return status;
    }

    struct poly1305_context poly1305_state = {0};
    struct chacha20_ctx     chacha20_state = {0};
    generatePoly1305Key(&poly1305_state, &chacha20_state, key, nonce);
    chacha20(&chacha20_state, dst, src, src_len);
    calculateMac(dst + src_len, &poly1305_state, dst, src_len, ad, ad_len);

    wCryptoZero(&poly1305_state, sizeof(poly1305_state));
    wCryptoZero(&chacha20_state, sizeof(chacha20_state));
    discard output_len;
    return kWCryptoOk;
}

wcrypto_status_t wCryptoSoftwareChacha20Poly1305Decrypt(unsigned char *dst, size_t dst_capacity,
                                                        const unsigned char *src, size_t src_len,
                                                        const unsigned char *ad, size_t ad_len,
                                                        const unsigned char nonce[WCRYPTO_CHACHA20POLY1305_NONCE_SIZE],
                                                        const unsigned char key[WCRYPTO_CHACHA20POLY1305_KEY_SIZE])
{
    size_t           plaintext_len = 0;
    wcrypto_status_t status =
        wCryptoValidateAeadDecrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key, &plaintext_len);
    if (status != kWCryptoOk)
    {
        wCryptoZero(dst, plaintext_len);
        return status;
    }

    struct poly1305_context poly1305_state         = {0};
    struct chacha20_ctx     chacha20_state         = {0};
    uint8_t                 mac[POLY1305_MAC_SIZE] = {0};

    generatePoly1305Key(&poly1305_state, &chacha20_state, key, nonce);
    calculateMac(mac, &poly1305_state, src, plaintext_len, ad, ad_len);
    if (! wCryptoEqual(mac, src + plaintext_len, sizeof(mac)))
    {
        status = kWCryptoAuthenticationFailed;
    }
    else
    {
        chacha20(&chacha20_state, dst, src, plaintext_len);
        status = kWCryptoOk;
    }

    if (status != kWCryptoOk)
    {
        wCryptoZero(dst, plaintext_len);
    }
    wCryptoZero(mac, sizeof(mac));
    wCryptoZero(&poly1305_state, sizeof(poly1305_state));
    wCryptoZero(&chacha20_state, sizeof(chacha20_state));
    return status;
}

wcrypto_status_t wCryptoSoftwareXChacha20Poly1305Encrypt(
    unsigned char *dst, size_t dst_capacity, const unsigned char *src, size_t src_len, const unsigned char *ad,
    size_t ad_len, const unsigned char nonce[WCRYPTO_XCHACHA20POLY1305_NONCE_SIZE],
    const unsigned char key[WCRYPTO_CHACHA20POLY1305_KEY_SIZE])
{
    size_t           output_len = 0;
    wcrypto_status_t status =
        wCryptoValidateAeadEncrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key, &output_len);
    if (status != kWCryptoOk)
    {
        wCryptoZero(dst, output_len);
        return status;
    }

    uint8_t subkey[CHACHA20_KEY_SIZE]               = {0};
    uint8_t derived_nonce[CHACHA20_IETF_NONCE_SIZE] = {0};
    memoryCopy(derived_nonce + 4, nonce + 16, 8);
    hchacha20(subkey, nonce, key);
    status = wCryptoSoftwareChacha20Poly1305Encrypt(dst, dst_capacity, src, src_len, ad, ad_len, derived_nonce, subkey);
    if (status != kWCryptoOk)
    {
        wCryptoZero(dst, output_len);
    }
    wCryptoZero(subkey, sizeof(subkey));
    return status;
}

wcrypto_status_t wCryptoSoftwareXChacha20Poly1305Decrypt(
    unsigned char *dst, size_t dst_capacity, const unsigned char *src, size_t src_len, const unsigned char *ad,
    size_t ad_len, const unsigned char nonce[WCRYPTO_XCHACHA20POLY1305_NONCE_SIZE],
    const unsigned char key[WCRYPTO_CHACHA20POLY1305_KEY_SIZE])
{
    size_t           output_len = 0;
    wcrypto_status_t status =
        wCryptoValidateAeadDecrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key, &output_len);
    if (status != kWCryptoOk)
    {
        wCryptoZero(dst, output_len);
        return status;
    }

    uint8_t subkey[CHACHA20_KEY_SIZE]               = {0};
    uint8_t derived_nonce[CHACHA20_IETF_NONCE_SIZE] = {0};
    memoryCopy(derived_nonce + 4, nonce + 16, 8);
    hchacha20(subkey, nonce, key);
    status = wCryptoSoftwareChacha20Poly1305Decrypt(dst, dst_capacity, src, src_len, ad, ad_len, derived_nonce, subkey);
    if (status != kWCryptoOk)
    {
        wCryptoZero(dst, output_len);
    }
    wCryptoZero(subkey, sizeof(subkey));
    return status;
}
