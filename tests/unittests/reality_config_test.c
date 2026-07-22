#include "RealityCommon/reality_v2.h"



static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void requireEqual(const uint8_t *actual, const uint8_t *expected, size_t len, const char *message)
{
    require(memcmp(actual, expected, len) == 0, message);
}

int main(void)
{
    require(wCryptoGlobalInit() == kWCryptoOk, "crypto global initialization failed");

    static const uint8_t expected_root_key[kRealityV2KeySize] = {
        0xb7, 0xb5, 0x29, 0x5c, 0x02, 0x33, 0x91, 0x5f, 0xf2, 0xb7, 0xfa, 0xac, 0x9f, 0x76, 0xe5, 0x70,
        0x6e, 0x2b, 0x4a, 0x1d, 0x46, 0x8d, 0x8c, 0x52, 0x9c, 0xf7, 0x2a, 0x08, 0xd4, 0x8a, 0xb7, 0x8b,
    };
    static const char max_password[]  = "pppppppppppppppppppppppppppppppp";
    static const char max_salt[]      = "ssssssssssssssssssssssssssssssss";
    static const char long_password[] = "ppppppppppppppppppppppppppppppppp";
    static const char long_salt[]     = "sssssssssssssssssssssssssssssssss";

    _Static_assert(sizeof(max_password) - 1 == kRealityV2MaxPasswordByteLength,
                   "root-key test password boundary drifted");
    _Static_assert(sizeof(max_salt) - 1 == kRealityV2MaxSaltByteLength, "root-key test salt boundary drifted");
    _Static_assert(sizeof(long_password) - 1 == kRealityV2MaxPasswordByteLength + 1,
                   "root-key oversized password fixture drifted");
    _Static_assert(sizeof(long_salt) - 1 == kRealityV2MaxSaltByteLength + 1, "root-key oversized salt fixture drifted");

    uint8_t root_key[kRealityV2KeySize];
    require(realityV2DeriveRootKey("p", "s", 1, root_key), "one-byte Reality credentials were rejected");
    require(realityV2DeriveRootKey(max_password, max_salt, 1, root_key),
            "maximum Reality credentials were rejected at one iteration");
    require(realityV2DeriveRootKey(max_password, max_salt, 3, root_key),
            "maximum Reality credentials were rejected at multiple iterations");

    require(! realityV2DeriveRootKey("", "s", 1, root_key), "empty Reality password was accepted");
    require(! realityV2DeriveRootKey("p", "", 1, root_key), "empty Reality salt was accepted");
    require(! realityV2DeriveRootKey(long_password, "s", 1, root_key),
            "oversized Reality password was accepted at one iteration");
    require(! realityV2DeriveRootKey("p", long_salt, 1, root_key), "oversized Reality salt was accepted");
    require(! realityV2DeriveRootKey("p", "s", 0, root_key), "zero Reality KDF iterations were accepted");
    require(! realityV2DeriveRootKey("p", "s", kRealityV2MaxKdfIterations + 1U, root_key),
            "out-of-range Reality KDF iterations were accepted");
    require(! realityV2DeriveRootKey(NULL, "s", 1, root_key) && ! realityV2DeriveRootKey("p", NULL, 1, root_key) &&
                ! realityV2DeriveRootKey("p", "s", 1, NULL),
            "null Reality KDF input was accepted");

    require(realityV2DeriveRootKey("reality-root-vector", "waterwall-reality", 12000, root_key),
            "fixed Reality root-key vector derivation failed");
    requireEqual(root_key,
                 expected_root_key,
                 sizeof(expected_root_key),
                 "Reality root-key derivation changed for a valid configuration");
    memset(root_key, 0, sizeof(root_key));
    wCryptoGlobalCleanup();
    return 0;
}
