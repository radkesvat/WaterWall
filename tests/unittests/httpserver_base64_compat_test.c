#include "HttpServer/http_base64.h"
#include "wwapi.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "ASSERT FAILED: %s\n", message);
        exit(1);
    }
}

static void requireDecodesA(const char *encoded)
{
    uint8_t output[4] = {0};
    size_t  output_length;

    require(httpserverBase64UrlDecodeCompat(encoded, output, sizeof(output), &output_length),
            "compatible HTTP Base64URL input was rejected");
    require(output_length == 1 && output[0] == 'a', "compatible HTTP Base64URL input decoded incorrectly");
}

int main(void)
{
    requireDecodesA("YQ");
    requireDecodesA("YQ==");
    requireDecodesA("YQ=");
    requireDecodesA("YQ=====");
    requireDecodesA(" \tY Q =\t=  ");

    uint8_t output[4]     = {0};
    size_t  output_length = 99;
    require(httpserverBase64UrlDecodeCompat("====", output, sizeof(output), &output_length),
            "historical padding-only input was rejected by the compatibility layer");
    require(output_length == 0, "padding-only input did not decode to an empty value");

    output_length = 99;
    require(! httpserverBase64UrlDecodeCompat("Y=Q", output, sizeof(output), &output_length),
            "a non-padding byte after terminal padding was accepted");
    require(output_length == 0, "failed compatibility decode did not clear output length");

    require(! wwBase64UrlDecode("YQ=", 3, output, sizeof(output), &output_length),
            "the generic decoder was accidentally made non-strict");

    puts("httpserver_base64_compat_test: all cases passed");
    return 0;
}
