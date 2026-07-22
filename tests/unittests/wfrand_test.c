#include "global_state.h"


static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

int main(void)
{
    uint8_t first[66];
    uint8_t second[64];

    memset(first, 0xA5, sizeof(first));
    memset(second, 0xA5, sizeof(second));

    require(secureRandomBytes(NULL, 0), "zero-sized secure random request failed");
    require(! secureRandomBytes(NULL, 1), "secure random accepted a NULL destination");
    require(! secureRandomBytes(second, sizeof(second)), "secure random worked before global initialization");
    require(globalstateInitializeSecureRandom(), "secure random global-state initialization failed");
    require(secureRandomBytes(first + 1, sizeof(first) - 2U), "first secure random request failed");
    require(secureRandomBytes(second, sizeof(second)), "second secure random request failed");
    require(first[0] == 0xA5 && first[sizeof(first) - 1U] == 0xA5, "secure random wrote outside its buffer");
    require(memcmp(first + 1, second, sizeof(second)) != 0, "independent secure random outputs matched");
    globalstateDestroySecureRandom();
    require(! secureRandomBytes(second, sizeof(second)), "secure random worked after global teardown");

    return 0;
}
