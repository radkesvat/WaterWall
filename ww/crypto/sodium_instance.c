#include "sodium_instance.h"

#include <sodium.h>
#include <stdio.h>

wcrypto_status_t sodiumGlobalInit(void)
{
    const int result = sodium_init();
    if (result < 0)
    {
        fprintf(stderr, "Sodium: refusing cryptography startup: sodium_init failed (result=%d)\n", result);
        return kWCryptoBackendFailed;
    }
    return kWCryptoOk;
}
