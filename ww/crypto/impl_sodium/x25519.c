#include "private/crypto_backends.h"
#include "private/crypto_validation.h"

#include <sodium.h>

wcrypto_status_t wCryptoSodiumX25519(unsigned char       out[WCRYPTO_X25519_KEY_SIZE],
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
    if (crypto_scalarmult(out, scalar, point) != 0)
    {
        wCryptoZero(out, WCRYPTO_X25519_KEY_SIZE);
        return kWCryptoRejectedKey;
    }
    return kWCryptoOk;
}
