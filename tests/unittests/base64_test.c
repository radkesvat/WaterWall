#include "wwapi.h"

typedef struct base64_vector_s
{
    const char *plain;
    const char *encoded;
    const char *padded;
} base64_vector_t;

static const base64_vector_t kVectors[] = {
    {"", "", ""},
    {"f", "Zg", "Zg=="},
    {"fo", "Zm8", "Zm8="},
    {"foo", "Zm9v", "Zm9v"},
    {"foob", "Zm9vYg", "Zm9vYg=="},
    {"fooba", "Zm9vYmE", "Zm9vYmE="},
    {"foobar", "Zm9vYmFy", "Zm9vYmFy"},
};

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "ASSERT FAILED: %s\n", message);
        exit(1);
    }
}

static void testEncodedSizes(void)
{
    for (size_t i = 0; i < ARRAY_SIZE(kVectors); ++i)
    {
        size_t encoded_size = SIZE_MAX;
        require(wwBase64UrlEncodedSizeNoPadding(stringLength(kVectors[i].plain), &encoded_size),
                "valid encoded-size calculation failed");
        require(encoded_size == stringLength(kVectors[i].encoded), "encoded-size calculation is wrong");
    }

    size_t unchanged = 123U;
    require(! wwBase64UrlEncodedSizeNoPadding(SIZE_MAX, &unchanged), "SIZE_MAX input did not overflow");
    require(unchanged == 123U, "overflowing encoded-size calculation modified its destination");
    require(! wwBase64UrlEncodedSizeNoPadding(SIZE_MAX - 1U, &unchanged), "near-SIZE_MAX input did not overflow");
    require(! wwBase64UrlEncodedSizeNoPadding(1, NULL), "NULL encoded-size destination was accepted");
}

static void testBase64UrlEncode(void)
{
    char output[32];

    for (size_t i = 0; i < ARRAY_SIZE(kVectors); ++i)
    {
        const size_t plain_length  = stringLength(kVectors[i].plain);
        size_t       output_length = SIZE_MAX;
        memorySet(output, 0xA5, sizeof(output));

        require(wwBase64UrlEncodeNoPadding(
                    (const uint8_t *) kVectors[i].plain, plain_length, output, sizeof(output), &output_length),
                "RFC Base64URL encode vector failed");
        require(output_length == stringLength(kVectors[i].encoded), "RFC encode vector returned the wrong length");
        require(stringCompare(output, kVectors[i].encoded) == 0, "RFC encode vector returned the wrong bytes");
    }

    const uint8_t url_input[] = {0xfb, 0xff, 0xbf};
    size_t        output_length;
    require(wwBase64UrlEncodeNoPadding(url_input, sizeof(url_input), output, sizeof(output), &output_length),
            "URL alphabet encode failed");
    require(output_length == 4 && stringCompare(output, "-_-_") == 0, "URL alphabet encode returned wrong bytes");

    char exact[2] = {'x', 'x'};
    require(wwBase64UrlEncodeNoPadding((const uint8_t *) "f", 1, exact, sizeof(exact), &output_length),
            "exact non-terminated capacity was rejected");
    require(output_length == sizeof(exact) && memoryCompare(exact, "Zg", sizeof(exact)) == 0,
            "exact non-terminated encode is wrong");

    char terminated[3] = {'x', 'x', 'x'};
    require(wwBase64UrlEncodeNoPadding((const uint8_t *) "f", 1, terminated, sizeof(terminated), &output_length),
            "terminated capacity was rejected");
    require(stringCompare(terminated, "Zg") == 0, "encoder did not write the optional terminator");

    output_length = 99;
    require(! wwBase64UrlEncodeNoPadding((const uint8_t *) "f", 1, output, 1, &output_length),
            "one-byte-short encode capacity was accepted");
    require(output_length == 0, "failed encode did not clear output length");

    output_length = 99;
    require(! wwBase64UrlEncodeNoPadding(NULL, 1, output, sizeof(output), &output_length),
            "NULL non-empty input was accepted");
    require(! wwBase64UrlEncodeNoPadding((const uint8_t *) "f", 1, NULL, sizeof(output), &output_length),
            "NULL output was accepted");

    uint8_t dummy = 0;
    require(! wwBase64UrlEncodeNoPadding(&dummy, SIZE_MAX, output, sizeof(output), &output_length),
            "overflowing encode length was accepted");
    require(output_length == 0, "overflowing encode did not clear output length");
}

static void requireDecode(const char *encoded, const char *expected)
{
    uint8_t output[32];
    size_t  output_length = SIZE_MAX;

    require(wwBase64UrlDecode(encoded, stringLength(encoded), output, sizeof(output), &output_length),
            "valid Base64URL input was rejected");
    require(output_length == stringLength(expected), "valid Base64URL input returned the wrong length");
    require(memoryCompare(output, expected, output_length) == 0, "valid Base64URL input returned the wrong bytes");
}

static void requireDecodeFailure(const char *encoded)
{
    uint8_t output[32];
    size_t  output_length = 99;

    require(! wwBase64UrlDecode(encoded, stringLength(encoded), output, sizeof(output), &output_length),
            "malformed Base64URL input was accepted");
    require(output_length == 0, "failed decode did not clear output length");
}

static void testBase64UrlDecode(void)
{
    for (size_t i = 0; i < ARRAY_SIZE(kVectors); ++i)
    {
        requireDecode(kVectors[i].encoded, kVectors[i].plain);
        requireDecode(kVectors[i].padded, kVectors[i].plain);
    }

    const char url_bytes[] = {(char) 0xfb, (char) 0xff, (char) 0xbf, '\0'};
    requireDecode("-_-_", url_bytes);

    requireDecodeFailure("A");
    requireDecodeFailure("YQ=");
    requireDecodeFailure("Y=Q=");
    requireDecodeFailure("=YQ=");
    requireDecodeFailure("YQ===");
    requireDecodeFailure("YQ==A");
    requireDecodeFailure("YQ+");
    requireDecodeFailure("YQ/");
    requireDecodeFailure("Y Q");
    requireDecodeFailure("YQ\n");

    uint8_t output[4];
    size_t  output_length = 99;
    require(! wwBase64UrlDecode("Zm8", 3, output, 1, &output_length), "insufficient decode capacity was accepted");
    require(output_length == 0, "capacity failure did not clear output length");

    require(! wwBase64UrlDecode(NULL, 1, output, sizeof(output), &output_length),
            "NULL non-empty decode input was accepted");
    require(! wwBase64UrlDecode("Zg", 2, NULL, 1, &output_length), "NULL decode output was accepted");
}

int main(void)
{
    testEncodedSizes();
    testBase64UrlEncode();
    testBase64UrlDecode();
    puts("base64_test: all cases passed");
    return 0;
}
