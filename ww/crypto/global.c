#include "private/crypto_config.h"
#include "private/crypto_validation.h"
#include "wcrypto.h"

#if defined(WCRYPTO_OPENSSL_RUNTIME_REQUIRED)
#include "openssl_instance.h"
#endif
#if defined(WCRYPTO_BACKEND_SODIUM)
#include "sodium_instance.h"
#endif

static atomic_bool crypto_initialized = ATOMIC_VAR_INIT(false);

bool wCryptoIsInitialized(void)
{
    return atomicLoadExplicit(&crypto_initialized, memory_order_acquire);
}

wcrypto_status_t wCryptoGlobalInit(void)
{
    if (wCryptoIsInitialized())
    {
        return kWCryptoOk;
    }

#if defined(WCRYPTO_OPENSSL_RUNTIME_REQUIRED) || defined(WCRYPTO_BACKEND_SODIUM)
    wcrypto_status_t status = kWCryptoOk;
#endif
#if defined(WCRYPTO_OPENSSL_RUNTIME_REQUIRED)
    status = opensslGlobalInit();
    if (status != kWCryptoOk)
    {
        return status;
    }
#endif

#if defined(WCRYPTO_BACKEND_SODIUM)
    status = sodiumGlobalInit();
    if (status != kWCryptoOk)
    {
#if defined(WCRYPTO_OPENSSL_RUNTIME_REQUIRED)
        opensslGlobalCleanup();
#endif
        return status;
    }
#endif

    atomicStoreExplicit(&crypto_initialized, true, memory_order_release);
    return kWCryptoOk;
}

void wCryptoGlobalCleanup(void)
{
    if (! wCryptoIsInitialized())
    {
        return;
    }

    atomicStoreExplicit(&crypto_initialized, false, memory_order_release);
#if defined(WCRYPTO_OPENSSL_RUNTIME_REQUIRED)
    opensslGlobalCleanup();
#endif
}
