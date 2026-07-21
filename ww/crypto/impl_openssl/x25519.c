#include "private/crypto_backends.h"
#include "private/crypto_validation.h"

#include <openssl/evp.h>

wcrypto_status_t wCryptoOpenSSLX25519(unsigned char       out[WCRYPTO_X25519_KEY_SIZE],
                                      const unsigned char scalar[WCRYPTO_X25519_KEY_SIZE],
                                      const unsigned char point[WCRYPTO_X25519_KEY_SIZE])
{
    wcrypto_status_t status = wCryptoValidateX25519(out, scalar, point);
    if (status != kWCryptoOk)
    {
        if (out != NULL)
        {
            wCryptoZero(out, WCRYPTO_X25519_KEY_SIZE);
        }
        return status;
    }

    EVP_PKEY     *privkey    = NULL;
    EVP_PKEY     *pubkey     = NULL;
    EVP_PKEY_CTX *ctx        = NULL;
    size_t        secret_len = WCRYPTO_X25519_KEY_SIZE;
    status                   = kWCryptoBackendFailed;

    privkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, scalar, WCRYPTO_X25519_KEY_SIZE);
    pubkey  = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, point, WCRYPTO_X25519_KEY_SIZE);
    if (privkey == NULL || pubkey == NULL)
    {
        goto cleanup;
    }
    ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (ctx == NULL || EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, pubkey) <= 0)
    {
        goto cleanup;
    }
    if (EVP_PKEY_derive(ctx, out, &secret_len) <= 0)
    {
        status = kWCryptoRejectedKey;
        goto cleanup;
    }
    status = secret_len == WCRYPTO_X25519_KEY_SIZE ? kWCryptoOk : kWCryptoBackendFailed;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pubkey);
    EVP_PKEY_free(privkey);
    if (status != kWCryptoOk)
    {
        wCryptoZero(out, WCRYPTO_X25519_KEY_SIZE);
    }
    return status;
}
