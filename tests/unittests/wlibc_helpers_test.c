#include "wlibc.h"
#include "wmath.h"
#include "wwapi.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "ASSERT FAILED: %s\n", message);
        exit(1);
    }
}

static void testBoolText(void)
{
    require(strcmp(boolToTrueFalse(true), "true") == 0, "boolToTrueFalse(true) failed");
    require(strcmp(boolToTrueFalse(false), "false") == 0, "boolToTrueFalse(false) failed");
    require(strcmp(boolToYesNo(true), "yes") == 0, "boolToYesNo(true) failed");
    require(strcmp(boolToYesNo(false), "no") == 0, "boolToYesNo(false) failed");
}

static void testAsciiCaseEqualsAny(void)
{
    static const char *const candidates[] = {"http", NULL, "https", "h2c"};
    size_t                   count        = ARRAY_SIZE(candidates);

    require(stringAsciiCaseEqualsAny("HTTP", candidates, count), "HTTP match failed");
    require(stringAsciiCaseEqualsAny("hTtPs", candidates, count), "hTtPs match failed");
    require(stringAsciiCaseEqualsAny("h2c", candidates, count), "h2c match failed");
    require(! stringAsciiCaseEqualsAny("ws", candidates, count), "ws should not match");
    require(! stringAsciiCaseEqualsAny("HTTP2", candidates, count), "HTTP2 should not match");
    require(! stringAsciiCaseEqualsAny(NULL, candidates, count), "NULL value should not match");
    require(! stringAsciiCaseEqualsAny("http", NULL, count), "NULL candidates should not match");
    require(! stringAsciiCaseEqualsAny("http", candidates, 0), "0 count should not match");
}

static bool appendFormatV(char *buffer, size_t capacity, size_t *offset, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    const bool result = stringAppendFormatV(buffer, capacity, offset, format, args);
    va_end(args);
    return result;
}

static void testStringAppendFormat(void)
{
    char   buf[32] = {0};
    size_t offset  = 0;

    require(appendFormatV(buf, sizeof(buf), &offset, "Hello %s!", "world"), "stringAppendFormatV failed");
    require(offset == 12, "wrong offset after first append");
    require(strcmp(buf, "Hello world!") == 0, "wrong content after first append");

    require(stringAppendFormat(buf, sizeof(buf), &offset, " Count: %d", 42), "stringAppendFormat second append failed");
    require(offset == 22, "wrong offset after second append");
    require(strcmp(buf, "Hello world! Count: 42") == 0, "wrong content after second append");

    char   exact[4]  = {0};
    size_t exact_off = 0;
    require(stringAppendFormat(exact, sizeof(exact), &exact_off, "%s", "abc"), "exact fit including terminator failed");
    require(exact_off == 3 && strcmp(exact, "abc") == 0, "exact fit produced the wrong result");

    char   one_short[3] = {0};
    size_t short_off    = 0;
    require(! stringAppendFormat(one_short, sizeof(one_short), &short_off, "%s", "abc"),
            "one-byte-short truncation was accepted");
    require(short_off == 0, "truncation modified the offset");

    char   empty[1]  = {'x'};
    size_t empty_off = 0;
    require(stringAppendFormat(empty, sizeof(empty), &empty_off, ""), "empty formatted output failed");
    require(empty_off == 0 && empty[0] == '\0', "empty formatted output changed the offset or omitted terminator");

    size_t invalid_off = sizeof(buf);
    require(! stringAppendFormat(buf, sizeof(buf), &invalid_off, "test"), "offset == capacity was accepted");
    require(invalid_off == sizeof(buf), "invalid offset was modified");

    invalid_off = sizeof(buf) + 1U;
    require(! stringAppendFormat(buf, sizeof(buf), &invalid_off, "test"), "offset > capacity was accepted");
    require(invalid_off == sizeof(buf) + 1U, "oversized offset was modified");

    offset = 0;
    require(! stringAppendFormat(NULL, sizeof(buf), &offset, "test"), "NULL buffer was accepted");
    require(! stringAppendFormat(buf, sizeof(buf), NULL, "test"), "NULL offset was accepted");
    require(! stringAppendFormat(buf, sizeof(buf), &offset, NULL), "NULL format was accepted");
    require(offset == 0, "invalid formatted append modified the offset");
}

static void testRotateLeft32(void)
{
    const uint32_t value = UINT32_C(0x12345678);

    require(wwRotateLeft32(value, 0) == UINT32_C(0x12345678), "rotate-left count 0 failed");
    require(wwRotateLeft32(value, 1) == UINT32_C(0x2468ACF0), "rotate-left count 1 failed");
    require(wwRotateLeft32(value, 7) == UINT32_C(0x1A2B3C09), "rotate-left count 7 failed");
    require(wwRotateLeft32(value, 31) == UINT32_C(0x091A2B3C), "rotate-left count 31 failed");
    require(wwRotateLeft32(value, 32) == UINT32_C(0x12345678), "rotate-left count 32 failed");
    require(wwRotateLeft32(value, 36) == UINT32_C(0x23456781), "rotate-left count greater than 32 failed");
}

int main(void)
{
    testBoolText();
    testAsciiCaseEqualsAny();
    testStringAppendFormat();
    testRotateLeft32();
    return 0;
}
