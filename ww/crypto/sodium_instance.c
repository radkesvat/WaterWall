#include "sodium_instance.h"

#include <sodium.h>

wcrypto_status_t sodiumGlobalInit(void)
{
    return sodium_init() < 0 ? kWCryptoBackendFailed : kWCryptoOk;
}
