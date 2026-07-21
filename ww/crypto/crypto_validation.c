#include "private/crypto_validation.h"

wcrypto_status_t wCryptoValidateHash(const void *out, const unsigned char *in, size_t inlen)
{
    if (out == NULL || (in == NULL && inlen != 0))
    {
        return kWCryptoInvalidArgument;
    }
    if (inlen > UINT32_MAX)
    {
        return kWCryptoInputTooLarge;
    }
    return kWCryptoOk;
}

wcrypto_status_t wCryptoValidateBlake2sInit(const void *ctx, size_t outlen, const unsigned char *key, size_t keylen)
{
    if (ctx == NULL || outlen == 0 || outlen > WCRYPTO_BLAKE2S_MAX_DIGEST_SIZE ||
        keylen > WCRYPTO_BLAKE2S_MAX_KEY_SIZE || (key == NULL && keylen != 0))
    {
        return kWCryptoInvalidArgument;
    }
    return kWCryptoOk;
}

wcrypto_status_t wCryptoValidateBlake2sUpdate(const void *ctx, const unsigned char *in, size_t inlen)
{
    if (ctx == NULL || (in == NULL && inlen != 0))
    {
        return kWCryptoInvalidArgument;
    }
    return kWCryptoOk;
}

wcrypto_status_t wCryptoValidateX25519(const unsigned char *out, const unsigned char *scalar,
                                       const unsigned char *point)
{
    return (out != NULL && scalar != NULL && point != NULL) ? kWCryptoOk : kWCryptoInvalidArgument;
}

static wcrypto_status_t validateAeadArguments(const unsigned char *src, size_t src_len, const unsigned char *ad,
                                              size_t ad_len, const unsigned char *nonce, const unsigned char *key)
{
    if ((src == NULL && src_len != 0) || (ad == NULL && ad_len != 0) || nonce == NULL || key == NULL)
    {
        return kWCryptoInvalidArgument;
    }
    return kWCryptoOk;
}

wcrypto_status_t wCryptoValidateAeadEncrypt(unsigned char *dst, size_t dst_capacity, const unsigned char *src,
                                            size_t src_len, const unsigned char *ad, size_t ad_len,
                                            const unsigned char *nonce, const unsigned char *key, size_t *output_len)
{
    if (output_len != NULL)
    {
        *output_len = 0;
    }
    if (src_len > WCRYPTO_AEAD_MAX_INPUT_SIZE - WCRYPTO_AEAD_TAG_SIZE || ad_len > WCRYPTO_AEAD_MAX_INPUT_SIZE)
    {
        return kWCryptoInputTooLarge;
    }

    /* Keep the complete ciphertext inside the common raw-input limit so every
     * accepted encryption result is also accepted by decryption. */
    const size_t required = src_len + WCRYPTO_AEAD_TAG_SIZE;
    if (dst == NULL || dst_capacity < required)
    {
        return kWCryptoInvalidArgument;
    }
    if (output_len != NULL)
    {
        *output_len = required;
    }

    wcrypto_status_t status = validateAeadArguments(src, src_len, ad, ad_len, nonce, key);
    if (status != kWCryptoOk)
    {
        return status;
    }
    return kWCryptoOk;
}

wcrypto_status_t wCryptoValidateAeadDecrypt(unsigned char *dst, size_t dst_capacity, const unsigned char *src,
                                            size_t src_len, const unsigned char *ad, size_t ad_len,
                                            const unsigned char *nonce, const unsigned char *key, size_t *output_len)
{
    if (output_len != NULL)
    {
        *output_len = 0;
    }
    if (src_len > WCRYPTO_AEAD_MAX_INPUT_SIZE || ad_len > WCRYPTO_AEAD_MAX_INPUT_SIZE)
    {
        return kWCryptoInputTooLarge;
    }
    if (src_len < WCRYPTO_AEAD_TAG_SIZE)
    {
        return kWCryptoInvalidArgument;
    }

    const size_t required = src_len - WCRYPTO_AEAD_TAG_SIZE;
    if (dst_capacity < required || (dst == NULL && (required != 0 || dst_capacity != 0)))
    {
        return kWCryptoInvalidArgument;
    }
    if (output_len != NULL)
    {
        *output_len = required;
    }

    wcrypto_status_t status = validateAeadArguments(src, src_len, ad, ad_len, nonce, key);
    if (status != kWCryptoOk)
    {
        return status;
    }
    return kWCryptoOk;
}
