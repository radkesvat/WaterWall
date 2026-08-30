#include "reality_close_lifecycle_test.h"
#include "wwapi.h"

#include "wcrypto.h"

int main(void)
{
    if (! globalstateInitializeSecureRandom())
    {
        fprintf(stderr, "FAIL: secure random initialization failed\n");
        return 1;
    }
    if (! frandGlobalInit())
    {
        fprintf(stderr, "FAIL: fast random initialization failed\n");
        globalstateDestroySecureRandom();
        return 1;
    }
    frandInit();
    if (wCryptoGlobalInit() != kWCryptoOk)
    {
        fprintf(stderr, "FAIL: crypto global initialization failed\n");
        frandThreadCleanup();
        frandGlobalCleanup();
        globalstateDestroySecureRandom();
        return 1;
    }
    realityTestClientCloseLifecycle();
    realityTestServerCloseLifecycle();
    realityTestClientRecordSizing();
    realityTestServerRecordSizing();
    wCryptoGlobalCleanup();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    return 0;
}
