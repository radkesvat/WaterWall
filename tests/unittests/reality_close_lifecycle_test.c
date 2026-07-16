#include "reality_close_lifecycle_test.h"

#include "global_state.h"
#include "wcrypto.h"

#if defined(WCRYPTO_BACKEND_SODIUM)
#include <sodium.h>
#endif
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
#if defined(WCRYPTO_BACKEND_SODIUM)
    if (sodium_init() == -1)
    {
        fprintf(stderr, "FAIL: sodium_init failed\n");
        return 1;
    }
#endif
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
    return 0;
}
