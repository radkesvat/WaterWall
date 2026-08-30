#pragma once

#include "ww_lwip.h"
#include "wwapi.h"

/* Fixtures that initialize lwIP directly own the same random/crypto lifecycle
 * that production establishes first. A tcpip_init() callback initializes that
 * thread's fast-RNG TLS and wwLwipShutdown() clears it. A raw lwip_init()
 * fixture uses the caller's TLS and erases the test ISN secret before cleanup. */
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
