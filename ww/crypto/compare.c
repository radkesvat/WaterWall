#include "private/crypto_config.h"
#include "wcrypto.h"

#if defined(WCRYPTO_BACKEND_OPENSSL)
#include <openssl/crypto.h>
#elif defined(WCRYPTO_BACKEND_SODIUM)
#include <sodium.h>
#endif

bool wCryptoEqual(const void *a, const void *b, size_t size)
{
    if (size == 0)
    {
        return true;
    }

#if defined(WCRYPTO_BACKEND_OPENSSL)
    return CRYPTO_memcmp(a, b, size) == 0;
#elif defined(WCRYPTO_BACKEND_SODIUM)
    return sodium_memcmp(a, b, size) == 0;
#else
    return memorySecureEqual(a, b, size);
#endif
}
