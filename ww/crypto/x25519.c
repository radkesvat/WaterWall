#include "private/crypto_backends.h"
#include "private/crypto_validation.h"
#include "wcrypto.h"

wcrypto_status_t wCryptoX25519(unsigned char       out[WCRYPTO_X25519_KEY_SIZE],
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
    if (! wCryptoIsInitialized())
    {
        wCryptoZero(out, WCRYPTO_X25519_KEY_SIZE);
        return kWCryptoInvalidState;
    }

#if defined(WCRYPTO_HAS_OPENSSL_X25519)
    status = wCryptoOpenSSLX25519(out, scalar, point);
#elif defined(WCRYPTO_HAS_SODIUM_X25519)
    status = wCryptoSodiumX25519(out, scalar, point);
#elif defined(WCRYPTO_HAS_SOFTWARE_X25519)
    status = wCryptoSoftwareX25519(out, scalar, point);
#else
    status = kWCryptoUnavailable;
#endif

    if (status != kWCryptoOk)
    {
        wCryptoZero(out, WCRYPTO_X25519_KEY_SIZE);
    }
    return status;
}
