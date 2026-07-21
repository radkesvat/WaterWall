#include "reality_close_lifecycle_test.h"

#include "global_state.h"
#include "wcrypto.h"

#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    if (wCryptoGlobalInit() != kWCryptoOk)
    {
        fprintf(stderr, "FAIL: crypto global initialization failed\n");
        return 1;
    }
    if (! globalstateInitializeSecureRandom())
    {
        fprintf(stderr, "FAIL: secure random initialization failed\n");
        return 1;
    }
    realityTestClientCloseLifecycle();
    realityTestServerCloseLifecycle();
    realityTestClientRecordSizing();
    realityTestServerRecordSizing();
    globalstateDestroySecureRandom();
    wCryptoGlobalCleanup();
    return 0;
}
