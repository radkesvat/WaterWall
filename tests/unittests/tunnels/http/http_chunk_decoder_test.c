/*
 * Covers incremental HTTP/1 chunk bodies, split framing, bounded metadata,
 * length-aware size validation, terminal errors and state publication.
 * Pure component coverage; node lifetime/input admission has separate fixtures.
 * CTest: waterwall.http_chunk_decoder_unit
 */
#include "HttpCommon/chunk_decoder.h"
#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

typedef struct chunk_fixture_s
{
    master_pool_t       *large;
    master_pool_t       *medium;
    master_pool_t       *small;
    buffer_pool_t       *pool;
    buffer_stream_t      stream;
    http_chunk_decoder_t decoder;
} chunk_fixture_t;

static void chunkSetup(chunk_fixture_t *fixture)
{
    *fixture        = (chunk_fixture_t) {0};
    fixture->large  = masterpoolCreateWithCapacity(16);
    fixture->medium = masterpoolCreateWithCapacity(16);
    fixture->small  = masterpoolCreateWithCapacity(16);
    fixture->pool =
        bufferpoolCreate(fixture->large, fixture->medium, fixture->small, 16, 32768, 8192, 1024, 32768, 32768);
    require(fixture->pool != NULL, "fixture buffer pool was rejected");
    bufferstreamInitEmpty(&fixture->stream, fixture->pool, 0);
}

static void chunkTeardown(chunk_fixture_t *fixture)
{
    bufferstreamDestroy(&fixture->stream);
    bufferpoolDestroy(fixture->pool);
    masterpoolMakeEmpty(fixture->large);
    masterpoolMakeEmpty(fixture->medium);
    masterpoolMakeEmpty(fixture->small);
    masterpoolDestroy(fixture->large);
    masterpoolDestroy(fixture->medium);
    masterpoolDestroy(fixture->small);
}

static void chunkPush(chunk_fixture_t *fixture, const void *bytes, size_t length)
{
    require(length > 0 && length <= UINT32_MAX, "invalid fixture delivery length");
    sbuf_t *input = bufferpoolGetBestFit(fixture->pool, (uint32_t) length, 0);
    memoryCopy(sbufGetMutablePtr(input), bytes, length);
    sbufSetLength(input, (uint32_t) length);
    bufferstreamPush(&fixture->stream, input);
}

static http_chunk_result_t chunkCollect(chunk_fixture_t *fixture, char *output, size_t capacity, size_t *used)
{
    while (true)
    {
        sbuf_t                   *body   = NULL;
        const http_chunk_result_t result = httpChunkDecoderStep(&fixture->decoder, &fixture->stream, &body);
        if (result != kHttpChunkData)
        {
            require(body == NULL, "non-data result transferred a body buffer");
            return result;
        }
        const size_t length = sbufGetLength(body);
        require(length > 0 && length <= kHttpChunkMaxOutputBytes, "body slice exceeded its bound");
        require(length <= capacity - *used, "decoder produced unexpected body bytes");
        memoryCopy(output + *used, sbufGetRawPtr(body), length);
        *used += length;
        require(fixture->decoder.phase == kHttpChunkBody || fixture->decoder.phase == kHttpChunkTail,
                "body result did not publish its next parser phase");
        bufferpoolReuseBuffer(fixture->pool, body);
    }
}

static void caseEverySplit(void)
{
    testCaseSet("chunk decoder preserves split size/extensions/tails/trailers");
    static const char wire[]         = "3; name=\"ignored\"\r\nabc\r\n2 \t\r\nde\r\n0\r\nX-Test: discarded\r\n\r\nNEXT";
    const size_t      message_length = sizeof(wire) - 1 - 4;
    for (size_t split = 1; split < message_length; ++split)
    {
        chunk_fixture_t fixture;
        chunkSetup(&fixture);
        char   output[5];
        size_t used = 0;
        chunkPush(&fixture, wire, split);
        require(chunkCollect(&fixture, output, sizeof(output), &used) == kHttpChunkNeedMore,
                "partial message was completed or rejected");
        require(bufferstreamGetBufLen(&fixture.stream) == 0, "partial framing retained peer bytes");
        chunkPush(&fixture, wire + split, sizeof(wire) - 1 - split);
        require(chunkCollect(&fixture, output, sizeof(output), &used) == kHttpChunkDone,
                "split message did not complete");
        require(used == 5 && memcmp(output, "abcde", 5) == 0, "split changed decoded body bytes");
        require(bufferstreamGetBufLen(&fixture.stream) == 4, "decoder consumed bytes after the message");
        uint8_t following[4];
        bufferstreamViewBytesAt(&fixture.stream, 0, following, sizeof(following));
        require(memcmp(following, "NEXT", 4) == 0, "decoder changed bytes after the message");
        chunkTeardown(&fixture);
    }
}

static void caseByteAtATime(void)
{
    testCaseSet("chunk decoder consumes metadata once with one-byte deliveries");
    chunk_fixture_t fixture;
    chunkSetup(&fixture);
    static const char wire[] = "4\r\nbody\r\n0;done=yes\r\nA: b\r\nB: c\r\n\r\n";
    char              output[4];
    size_t            used = 0;
    for (size_t i = 0; i < sizeof(wire) - 1; ++i)
    {
        chunkPush(&fixture, wire + i, 1);
        const http_chunk_result_t result = chunkCollect(&fixture, output, sizeof(output), &used);
        require(result == (i == sizeof(wire) - 2 ? kHttpChunkDone : kHttpChunkNeedMore),
                "one-byte delivery changed decoder completion");
        require(bufferstreamGetBufLen(&fixture.stream) == 0, "one-byte framing stayed buffered");
    }
    require(used == 4 && memcmp(output, "body", 4) == 0, "one-byte delivery changed the body");
    chunkTeardown(&fixture);
}

static void caseHugeDeclaration(bool coalesced)
{
    testCaseSet(coalesced ? "1 GiB chunk drains a coalesced 4 MiB body delivery"
                          : "1 GiB chunk drains each progressive body delivery");
    chunk_fixture_t fixture;
    chunkSetup(&fixture);
    chunkPush(&fixture, "40000000\r\n", 10);
    sbuf_t *body = NULL;
    require(httpChunkDecoderStep(&fixture.decoder, &fixture.stream, &body) == kHttpChunkNeedMore,
            "huge declaration was rejected before body bytes");
    require(fixture.decoder.remaining == UINT64_C(1073741824), "huge declaration lost its length");

    const uint32_t total    = 4 * 1024 * 1024;
    const uint32_t delivery = coalesced ? total : 4096;
    uint8_t       *bytes    = memoryAllocate(delivery);
    uint32_t       decoded  = 0;
    for (uint32_t offset = 0; offset < total; offset += delivery)
    {
        for (uint32_t i = 0; i < delivery; ++i)
            bytes[i] = (uint8_t) ((offset + i) % 251);
        chunkPush(&fixture, bytes, delivery);
        http_chunk_result_t result;
        while ((result = httpChunkDecoderStep(&fixture.decoder, &fixture.stream, &body)) == kHttpChunkData)
        {
            const uint32_t length = sbufGetLength(body);
            require(length > 0 && length <= kHttpChunkMaxOutputBytes, "large body output exceeded 16 KiB");
            for (uint32_t i = 0; i < length; ++i)
                require(((const uint8_t *) sbufGetRawPtr(body))[i] == (uint8_t) ((decoded + i) % 251),
                        "large body byte order changed");
            decoded += length;
            require(fixture.decoder.remaining == UINT64_C(1073741824) - decoded,
                    "remaining body length was stale at output");
            bufferpoolReuseBuffer(fixture.pool, body);
        }
        require(result == kHttpChunkNeedMore && body == NULL, "incomplete large body did not await input");
        require(decoded == offset + delivery, "large chunk body was held for the full declaration");
        require(bufferstreamGetCharge(&fixture.stream) == 0 && bufferstreamGetEntryCount(&fixture.stream) == 0,
                "drained large body retained allocation charge");
    }
    memoryFree(bytes);
    chunkTeardown(&fixture);
}

static void caseInvalidSize(const void *bytes, size_t length)
{
    chunk_fixture_t fixture;
    chunkSetup(&fixture);
    chunkPush(&fixture, bytes, length);
    sbuf_t *body = NULL;
    require(httpChunkDecoderStep(&fixture.decoder, &fixture.stream, &body) == kHttpChunkError,
            "invalid chunk size was accepted");
    require(body == NULL, "invalid size emitted body bytes");
    require(httpChunkDecoderStep(&fixture.decoder, &fixture.stream, &body) == kHttpChunkError,
            "decoder error was not terminal");
    chunkTeardown(&fixture);
}

static void caseSizeValidation(void)
{
    testCaseSet("chunk size parser rejects signs, prefixes, overflow and embedded controls");
    static const char *invalid[] = {"\r\n",
                                    "+1\r\n",
                                    "-1\r\n",
                                    "0x1\r\n",
                                    " 1\r\n",
                                    "1 2\r\n",
                                    "g\r\n",
                                    "8000000000000000\r\n",
                                    "ffffffffffffffff\r\n",
                                    "1\n",
                                    "1\rx",
                                    "1;\x01\r\n"};
    for (size_t i = 0; i < ARRAY_SIZE(invalid); ++i)
        caseInvalidSize(invalid[i], strlen(invalid[i]));
    static const char nul_size[]      = {'1', '\0', 'f', '\r', '\n'};
    static const char nul_extension[] = {'1', ';', 'x', '\0', '\r', '\n'};
    caseInvalidSize(nul_size, sizeof(nul_size));
    caseInvalidSize(nul_extension, sizeof(nul_extension));

    chunk_fixture_t fixture;
    chunkSetup(&fixture);
    chunkPush(&fixture, "7FFFFFFFFFFFFFFF\r\n", 18);
    sbuf_t *body = NULL;
    require(httpChunkDecoderStep(&fixture.decoder, &fixture.stream, &body) == kHttpChunkNeedMore &&
                fixture.decoder.remaining == INT64_MAX,
            "maximum supported chunk size was rejected");
    chunkTeardown(&fixture);
}

static void caseSizeLineLimit(void)
{
    testCaseSet("chunk size line counts extensions and CRLF in its 1 KiB limit");
    char line[kHttpChunkMaxSizeLineBytes + 1];
    memorySet(line, 'a', sizeof(line));
    line[0]                              = '1';
    line[1]                              = ';';
    line[kHttpChunkMaxSizeLineBytes - 2] = '\r';
    line[kHttpChunkMaxSizeLineBytes - 1] = '\n';
    chunk_fixture_t fixture;
    chunkSetup(&fixture);
    chunkPush(&fixture, line, kHttpChunkMaxSizeLineBytes);
    sbuf_t *body = NULL;
    require(httpChunkDecoderStep(&fixture.decoder, &fixture.stream, &body) == kHttpChunkNeedMore &&
                fixture.decoder.phase == kHttpChunkBody && fixture.decoder.remaining == 1,
            "exact-limit size line was rejected");
    chunkTeardown(&fixture);

    line[kHttpChunkMaxSizeLineBytes - 2] = 'a';
    line[kHttpChunkMaxSizeLineBytes - 1] = '\r';
    line[kHttpChunkMaxSizeLineBytes]     = '\n';
    caseInvalidSize(line, sizeof(line));
    memorySet(line + 2, 'a', sizeof(line) - 2);
    caseInvalidSize(line, kHttpChunkMaxSizeLineBytes);
}

static void caseTrailerLimit(bool many_lines, bool overflow)
{
    testCaseSet(many_lines ? "chunk trailer aggregate limit counts every discarded line"
                           : "chunk trailer limit bounds a CRLF-less line");
    chunk_fixture_t fixture;
    chunkSetup(&fixture);
    chunkPush(&fixture, "0\r\n", 3);
    char         trailer[kHttpChunkMaxTrailerBytes + 1];
    const size_t length = kHttpChunkMaxTrailerBytes + (overflow ? 1 : 0);
    memorySet(trailer, 't', sizeof(trailer));
    if (many_lines)
    {
        for (size_t i = 63; i + 2 < length - 4; i += 64)
        {
            trailer[i - 1] = '\r';
            trailer[i]     = '\n';
        }
    }
    memoryCopy(trailer + length - 4, "\r\n\r\n", 4);
    chunkPush(&fixture, trailer, length);
    sbuf_t *body = NULL;
    require(httpChunkDecoderStep(&fixture.decoder, &fixture.stream, &body) ==
                (overflow ? kHttpChunkError : kHttpChunkDone),
            "trailer aggregate limit accepted overflow or rejected its boundary");
    require(body == NULL, "trailers emitted body output");
    chunkTeardown(&fixture);

    if (! many_lines && overflow)
    {
        chunkSetup(&fixture);
        chunkPush(&fixture, "0\r\n", 3);
        memorySet(trailer, 't', sizeof(trailer));
        chunkPush(&fixture, trailer, kHttpChunkMaxTrailerBytes);
        require(httpChunkDecoderStep(&fixture.decoder, &fixture.stream, &body) == kHttpChunkError,
                "CRLF-less trailers stayed open at their limit");
        chunkTeardown(&fixture);
    }
}

static void caseTailAfterDelivery(void)
{
    testCaseSet("chunk decoder publishes body progress before validating a later tail");
    chunk_fixture_t fixture;
    chunkSetup(&fixture);
    chunkPush(&fixture, "3\r\nabc", 6);
    sbuf_t *body = NULL;
    require(httpChunkDecoderStep(&fixture.decoder, &fixture.stream, &body) == kHttpChunkData,
            "body waited for the terminator");
    require(fixture.decoder.phase == kHttpChunkTail && fixture.decoder.remaining == 0,
            "last body slice left stale parser state");
    require(sbufGetLength(body) == 3 && memcmp(sbufGetRawPtr(body), "abc", 3) == 0,
            "body output changed before the terminator");
    bufferpoolReuseBuffer(fixture.pool, body);
    chunkPush(&fixture, "\r", 1);
    require(httpChunkDecoderStep(&fixture.decoder, &fixture.stream, &body) == kHttpChunkNeedMore,
            "partial tail was rejected");
    chunkPush(&fixture, "x", 1);
    require(httpChunkDecoderStep(&fixture.decoder, &fixture.stream, &body) == kHttpChunkError && body == NULL,
            "malformed later terminator was accepted");
    chunkTeardown(&fixture);
}

int main(void)
{
    caseEverySplit();
    caseByteAtATime();
    caseHugeDeclaration(false);
    caseHugeDeclaration(true);
    caseSizeValidation();
    caseSizeLineLimit();
    for (unsigned layout = 0; layout < 2; ++layout)
        for (unsigned overflow = 0; overflow < 2; ++overflow)
            caseTrailerLimit(layout != 0, overflow != 0);
    caseTailAfterDelivery();
    return 0;
}
