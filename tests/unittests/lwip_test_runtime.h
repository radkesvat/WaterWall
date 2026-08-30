#pragma once

#include "ww_lwip.h"
#include "wwapi.h"

/* Direct tcpip_init() fixtures own the same random/crypto lifecycle that
 * production establishes before lwIP starts. The tcpip init callback still
 * initializes that thread's fast-RNG TLS, and wwLwipShutdown() clears it. */
static inline bool lwipTestRuntimeInitialize(void)
{
    if (! globalstateInitializeSecureRandom())
    {
        return false;
    }
    if (! frandGlobalInit())
    {
        globalstateDestroySecureRandom();
        return false;
    }
    frandInit();

    if (wCryptoGlobalInit() != kWCryptoOk)
    {
        frandThreadCleanup();
        frandGlobalCleanup();
        globalstateDestroySecureRandom();
        return false;
    }

    wwLwipInitializeProtocolState();
    return true;
}

static inline void lwipTestRuntimeCleanup(void)
{
    wCryptoGlobalCleanup();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
}
