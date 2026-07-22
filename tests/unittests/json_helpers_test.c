#include "utils/json_helpers.h"



static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void requireParsed(const char *value, uint64_t expected)
{
    uint64_t parsed = 0;

    require(jsonParseUint64String(value, &parsed), "valid uint64 string was rejected");
    require(parsed == expected, "valid uint64 string produced the wrong value");
}

static void requireRejected(const char *value)
{
    uint64_t parsed = 123U;

    require(! jsonParseUint64String(value, &parsed), "invalid uint64 string was accepted");
    require(parsed == 123U, "rejected uint64 string modified the destination");
}

int main(void)
{
    requireParsed("0", 0U);
    requireParsed("42", 42U);
    requireParsed(" 42\t", 42U);
    requireParsed("18446744073709551615", UINT64_MAX);

    requireRejected(NULL);
    requireRejected("");
    requireRejected(" \t\r\n");
    requireRejected("-1");
    requireRejected(" -1");
    requireRejected("+1");
    requireRejected("1x");
    requireRejected("1 2");
    requireRejected("18446744073709551616");
    return 0;
}
