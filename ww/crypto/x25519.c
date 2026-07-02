#include "wcrypto.h"
#include "wlibc.h"

#include "private/crypto_backends.h"

int performX25519(unsigned char out[32], const unsigned char scalar[32], const unsigned char point[32])
{
#if defined(WCRYPTO_HAS_OPENSSL_X25519)
    return wCryptoOpenSSLX25519(out, scalar, point);
#elif defined(WCRYPTO_HAS_SODIUM_X25519)
    return wCryptoSodiumX25519(out, scalar, point);
#elif defined(WCRYPTO_HAS_SOFTWARE_X25519)
    return wCryptoSoftwareX25519(out, scalar, point);
#else
    discard out;
    discard scalar;
    discard point;
    return -1;
#endif
}
