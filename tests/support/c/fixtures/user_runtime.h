/* Direct object fixtures establish the same random/crypto prerequisites as
 * createGlobalState(), without starting workers or network resources. */
#pragma once

#include "global_state.h"
#include "wcrypto.h"
#include "wfrand.h"

static inline bool userTestRuntimeInitialize(void)
{
    if (! globalstateInitializeSecureRandom())
        return false;
    if (! frandGlobalInit())
    {
        globalstateDestroySecureRandom();
        return false;
    }
    frandInit();
    if (wCryptoGlobalInit() == kWCryptoOk)
        return true;
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    return false;
}

static inline void userTestRuntimeCleanup(void)
{
    wCryptoGlobalCleanup();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
}
