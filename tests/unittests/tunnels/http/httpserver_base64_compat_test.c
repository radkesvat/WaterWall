/*
 * Covers: httpserver base64 compat; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Checks: Assertion labels include: compatible HTTP Base64URL input was rejected; compatible HTTP Base64URL
 * input decoded incorrectly; YQ; YQ==
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.httpserver_base64_compat_unit
 */
#include "HttpServer/http_base64.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)
#include "wwapi.h"


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
    testCaseSet("httpserver_base64_compat_test");
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
