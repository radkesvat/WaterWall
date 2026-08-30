/* Unit tests for HttpClient HTTP/1.1 split pairing-ID generation. */
#include "HttpClient/structure.h"
#include "wfrand.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void setupDeterministicRng(void)
{
    static const uint8_t test_key[32] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba,
                                         0x98, 0x76, 0x54, 0x32, 0x10, 0x55, 0xaa, 0x55, 0xaa, 0x33, 0xcc,
                                         0x33, 0xcc, 0x0f, 0xf0, 0x0f, 0xf0, 0xa5, 0x5a, 0xa5, 0x5a};
    wfrandTestReset(test_key, 0);
}

static void caseGenerateIdUsesTwoFastRand64Values(void)
{
    setupDeterministicRng();
    const uint64_t expected_high = fastRand64();
    const uint64_t expected_low  = fastRand64();
    const uint64_t expected_next = fastRand64();

    char expected[kHttpClientSplitIdCapacity];
    require(snprintf(expected, sizeof(expected), "%016" PRIx64 "%016" PRIx64, expected_high, expected_low) ==
                kHttpClientSplitIdHexChars,
            "failed to format the expected split ID");

    uint8_t buffer[64];
    memset(buffer, 0xA5, sizeof(buffer));

    const size_t offset = 10;
    char        *id_out = (char *) (buffer + offset);

    setupDeterministicRng();
    require(httpclientSplitGenerateId(id_out, kHttpClientSplitIdCapacity), "split-ID generation failed");
    require(strcmp(id_out, expected) == 0, "split ID was not built from two consecutive fastRand64 values");

    const uint64_t actual_next = fastRand64();
    require(actual_next == expected_next,
            "split-ID generation did not consume exactly two fastRand64 values (16 bytes)");

    require(strlen(id_out) == kHttpClientSplitIdHexChars, "split ID length was not exactly 32 hexadecimal characters");

    for (size_t i = 0; i < kHttpClientSplitIdHexChars; ++i)
    {
        char c            = id_out[i];
        bool is_lower_hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        require(is_lower_hex, "split ID contains non-lowercase-hexadecimal characters");
    }

    require(id_out[kHttpClientSplitIdHexChars] == '\0', "split ID was not null-terminated at declared capacity");

    for (size_t i = 0; i < offset; ++i)
    {
        require(buffer[i] == 0xA5, "sentinel byte before output buffer was overwritten");
    }
    for (size_t i = offset + kHttpClientSplitIdCapacity; i < sizeof(buffer); ++i)
    {
        require(buffer[i] == 0xA5, "sentinel byte after output buffer was overwritten");
    }
}

static void caseGenerateIdRejectsInvalidBuffersWithoutAdvancingRandomState(void)
{
    setupDeterministicRng();
    const uint64_t expected_first = fastRand64();

    char too_small[kHttpClientSplitIdHexChars];
    memset(too_small, 0x5A, sizeof(too_small));

    setupDeterministicRng();
    require(! httpclientSplitGenerateId(too_small, sizeof(too_small)),
            "split ID generation accepted an undersized buffer");
    require(too_small[0] == '\0', "undersized split-ID output retained stale data");
    require(fastRand64() == expected_first, "undersized output advanced the fast random state");

    setupDeterministicRng();
    require(! httpclientSplitGenerateId(NULL, kHttpClientSplitIdCapacity), "split ID generation accepted NULL output");
    require(fastRand64() == expected_first, "NULL output advanced the fast random state");
}

int main(void)
{
    require(globalstateInitializeSecureRandom(), "secure random provider initialization failed");
    require(frandGlobalInit(), "fast random global initialization failed");
    frandInit();

    caseGenerateIdUsesTwoFastRand64Values();
    caseGenerateIdRejectsInvalidBuffersWithoutAdvancingRandomState();
    puts("httpclient_split_id_test: all cases passed");

    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    return 0;
}
