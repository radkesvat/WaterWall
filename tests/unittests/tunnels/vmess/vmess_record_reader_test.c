/*
 * Covers: shared VMess framed-record assembly and reservation ownership.
 * Setup: ordinary local pools, a bounded queue and real VMess body codecs; no
 * workers, callbacks, sockets or protocol nodes are needed.
 * Cases: fragmented prefix/body, received-byte admission, immediate allocation
 * charge, malformed length/body/EOF, complete output padding and coalesced FIFO.
 * Checks: exact source consumption, retained costs, caller-owned suffixes and
 * zero budget usage after partial/error cleanup. Mode vectors stay in crypto_test.
 * CTest: waterwall.vmess_record_reader_unit in Debug and Release.
 */
#include "VmessCommon/record_reader.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

typedef struct reader_fixture_s
{
    buffer_budget_t             budget;
    buffer_queue_t              pending;
    sbuf_t                     *head;
    buffer_budget_reservation_t reservation;
    vmess_record_reader_t       reader;
    vmess_body_ctx_t            rx;
    vmess_body_ctx_t            tx;
} reader_fixture_t;

static buffer_pool_t *pool;
static master_pool_t *masters[3];
static const uint8_t  key[16]   = {1, 2, 3, 4};
static const uint8_t  iv[16]    = {5, 6, 7, 8};
static const uint8_t  message[] = "record reader payload";

static void begin(reader_fixture_t *fixture, size_t bytes, size_t charge, uint8_t security, uint8_t options)
{
    *fixture = (reader_fixture_t) {0};
    bufferbudgetInit(&fixture->budget, (buffer_budget_cost_t) {.bytes = bytes, .charge = charge});
    bufferqueueInitEmpty(&fixture->pending);
    require(bufferqueueTryAttachBudget(&fixture->pending, &fixture->budget), "empty input queue did not attach");
    vmessRecordReaderInit(&fixture->reader, pool, &fixture->budget);
    require(vmessBodyInit(&fixture->rx, key, iv, security, options, 1, false, kVmessCounterWrap) == kWCryptoOk &&
                vmessBodyInit(&fixture->tx, key, iv, security, options, 1, true, kVmessCounterWrap) == kWCryptoOk,
            "record codecs did not initialize");
}

static void end(reader_fixture_t *fixture)
{
    vmessRecordReaderDestroy(&fixture->reader);
    vmessRecordReaderDestroy(&fixture->reader);
    if (fixture->head != NULL)
    {
        bufferbudgetReservationRelease(&fixture->reservation);
        bufferpoolReuseBuffer(pool, fixture->head);
        fixture->head = NULL;
    }
    sbuf_t *queued;
    while ((queued = bufferqueuePopFront(&fixture->pending)) != NULL)
        bufferpoolReuseBuffer(pool, queued);
    bufferqueueDestroy(&fixture->pending);
    require(fixture->budget.used.bytes == 0 && fixture->budget.used.charge == 0,
            "reader/source destruction leaked budget usage");
    vmessBodyDestroy(&fixture->rx);
    vmessBodyDestroy(&fixture->tx);
}

static sbuf_t *append(reader_fixture_t *fixture, const uint8_t *bytes, size_t length)
{
    sbuf_t *input = bufferpoolGetSmallBuffer(pool);
    require(length <= sbufGetWritableCapacity(input), "test input exceeded small pool capacity");
    sbufSetLength(input, (uint32_t) length);
    if (length != 0)
        sbufWrite(input, bytes, (uint32_t) length);
    require(bufferqueueTryPushBack(&fixture->pending, &input), "fixture input was refused");
    return input;
}

static vmess_record_result_t readRecord(reader_fixture_t *fixture)
{
    const vmess_record_input_t input = {
        .pending = &fixture->pending, .head = &fixture->head, .reservation = &fixture->reservation};
    return vmessRecordReaderRead(&fixture->reader, &fixture->rx, &input);
}

static size_t seal(reader_fixture_t *fixture, uint8_t wire[256], bool eof)
{
    size_t length = 0;
    require(vmessBodySeal(&fixture->tx, eof ? NULL : message, eof ? 0 : sizeof(message) - 1, eof, wire, 256, &length) ==
                kWCryptoOk,
            "fixture record did not seal");
    return length;
}

static void checkOutput(vmess_record_result_t result)
{
    require(result.status == kVmessRecordPayload && result.payload != NULL, "record did not return plaintext");
    require(! sbufIsSplice(result.payload) && sbufGetLength(result.payload) == sizeof(message) - 1 &&
                memoryEqual(sbufGetRawPtr(result.payload), message, sizeof(message) - 1),
            "plaintext bytes differ");
    uint16_t padding = bufferpoolGetLargeBufferPadding(pool);
    require(sbufGetHeadroom(result.payload) >= padding && sbufGetInitialHeadroom(result.payload) >= padding,
            "plaintext lost full onward padding");
    sbufShiftLeft(result.payload, padding);
    memset(sbufGetMutablePtr(result.payload), 0x5a, padding);
    bufferpoolReuseBuffer(pool, result.payload);
}

static void testFragmentedRecord(void)
{
    reader_fixture_t fixture;
    begin(&fixture, 4096, 16384, VMESS_SECURITY_AES128_GCM, VMESS_OPTION_CHUNK | VMESS_OPTION_AUTH_LENGTH);
    uint8_t wire[256];
    size_t  length = seal(&fixture, wire, false);
    require(vmessBodyLengthSize(&fixture.rx) == 18, "fixture expected authenticated length");
    append(&fixture, wire, 1);
    vmess_record_result_t result = readRecord(&fixture);
    require(result.status == kVmessRecordNeedMore && result.payload == NULL && result.consumed == 1 &&
                fixture.budget.used.bytes == 1 && fixture.budget.used.charge == 0 && fixture.reader.prefix_filled == 1,
            "partial prefix lost logical reservation or retained exhausted storage");
    append(&fixture, NULL, 0);
    append(&fixture, wire + 1, 18);
    result = readRecord(&fixture);
    require(result.status == kVmessRecordNeedMore && result.consumed == 18 && fixture.reader.prefix_filled == 0 &&
                fixture.reader.body_filled == 1 && fixture.reader.body_length == length - 18 &&
                fixture.reader.body_reservation.cost.bytes == 1 && fixture.budget.used.bytes == 1 &&
                fixture.budget.used.charge == sbufGetQueueCharge(fixture.reader.body),
            "partial body reserved announced bytes or failed to charge its allocation");
    append(&fixture, wire + 19, length - 19);
    result = readRecord(&fixture);
    require(result.consumed == length - 19 && fixture.budget.used.bytes == 0 && fixture.budget.used.charge == 0 &&
                fixture.reader.body == NULL && fixture.rx.counter == 1,
            "completed record retained reservations or advanced codec incorrectly");
    checkOutput(result);
    end(&fixture);
}

static void testPartialCleanup(void)
{
    for (unsigned body = 0; body < 2; ++body)
    {
        reader_fixture_t fixture;
        begin(&fixture, body ? 19 : 1, 16384, VMESS_SECURITY_AES128_GCM, VMESS_OPTION_CHUNK | VMESS_OPTION_AUTH_LENGTH);
        uint8_t wire[256];
        size_t  length = seal(&fixture, wire, false);
        append(&fixture, wire, body ? 19 : 1);
        vmess_record_result_t result = readRecord(&fixture);
        require(result.status == kVmessRecordNeedMore && fixture.budget.used.bytes == 1,
                "small logical limit refused a partial record based on announced length");
        if (body)
            require(fixture.reader.body_length == length - 18 &&
                        fixture.reader.body_length > fixture.budget.limits.bytes,
                    "fixture did not exceed announced-body allowance");
        end(&fixture);
    }
}

static void testAllocationLimit(void)
{
    buffer_pool_fit_t body_fit;
    require(bufferpoolQueryBestFit(pool, sizeof(message) - 1 + 16, bufferpoolGetLargeBufferPadding(pool), &body_fit),
            "body allocation query failed");
    sbuf_t *probe         = bufferpoolGetSmallBuffer(pool);
    size_t  source_charge = sbufGetQueueCharge(probe);
    bufferpoolReuseBuffer(pool, probe);
    reader_fixture_t fixture;
    begin(&fixture,
          4096,
          source_charge + body_fit.allocation_charge - 1,
          VMESS_SECURITY_AES128_GCM,
          VMESS_OPTION_CHUNK | VMESS_OPTION_AUTH_LENGTH);
    uint8_t               wire[256];
    size_t                length = seal(&fixture, wire, false);
    sbuf_t               *source = append(&fixture, wire, length);
    vmess_record_result_t result = readRecord(&fixture);
    require(result.status == kVmessRecordLimitError && result.payload == NULL && result.consumed == 18 &&
                fixture.head == source && sbufGetLength(source) == length - 18 &&
                fixture.budget.used.bytes == length - 18 && fixture.budget.used.charge == source_charge,
            "body charge refusal consumed source body or released live source charge");
    vmessRecordReaderDestroy(&fixture.reader);
    require(fixture.head == source && fixture.budget.used.charge == source_charge &&
                memoryEqual(sbufGetRawPtr(source), wire + 18, length - 18),
            "reader destruction released borrowed source ownership");
    end(&fixture);
}

static void testCoalescedRecords(void)
{
    reader_fixture_t fixture;
    begin(&fixture, 4096, 16384, VMESS_SECURITY_AES128_GCM, VMESS_OPTION_CHUNK);
    uint8_t first[256], second[256], combined[256];
    size_t  first_length  = seal(&fixture, first, false);
    size_t  second_length = seal(&fixture, second, false);
    memcpy(combined, first, first_length);
    memcpy(combined + first_length, second, second_length);
    sbuf_t               *source        = append(&fixture, combined, first_length + second_length);
    sbuf_t               *tail          = append(&fixture, (const uint8_t *) "unread", 6);
    size_t                source_charge = sbufGetQueueCharge(source);
    size_t                tail_charge   = sbufGetQueueCharge(tail);
    vmess_record_result_t result        = readRecord(&fixture);
    require(result.consumed == first_length && fixture.head == source && sbufGetLength(source) == second_length &&
                fixture.budget.used.bytes == second_length + 6 &&
                fixture.budget.used.charge == source_charge + tail_charge && fixture.rx.counter == 1,
            "first output changed coalesced suffix accounting or codec ordinal");
    checkOutput(result);
    result = readRecord(&fixture);
    require(result.consumed == second_length && fixture.head == NULL && fixture.budget.used.bytes == 6 &&
                fixture.budget.used.charge == tail_charge && bufferqueueFront(&fixture.pending) == tail,
            "second output consumed following queue entry or retained source charge");
    checkOutput(result);
    vmessRecordReaderDestroy(&fixture.reader);
    require(bufferqueueFront(&fixture.pending) == tail && fixture.budget.used.bytes == 6,
            "reader destruction took ownership of a queued suffix");
    end(&fixture);
}

static void testTerminalRecords(void)
{
    for (unsigned kind = 0; kind < 4; ++kind)
    {
        reader_fixture_t fixture;
        begin(&fixture, 4096, 16384, VMESS_SECURITY_AES128_GCM, VMESS_OPTION_CHUNK | VMESS_OPTION_AUTH_LENGTH);
        uint8_t wire[256];
        size_t  length = seal(&fixture, wire, kind >= 2);
        if (kind == 0)
            wire[17] ^= 1;
        else if (kind == 1 || kind == 2)
            wire[length - 1] ^= 1;
        append(&fixture, wire, length);
        vmess_record_result_t result   = readRecord(&fixture);
        vmess_record_status_t expected = kind == 0   ? kVmessRecordLengthError
                                         : kind == 3 ? kVmessRecordEof
                                                     : kVmessRecordBodyError;
        require(result.status == expected && result.payload == NULL && result.consumed == (kind == 0 ? 18 : length),
                "terminal record returned wrong status, plaintext or consumption");
        if (kind != 0)
            require(fixture.budget.used.bytes == 0 && fixture.budget.used.charge == 0,
                    "body authentication/EOF result retained completed storage");
        require(fixture.rx.ended == (kind == 3), "unauthenticated empty record became EOF");
        end(&fixture);
    }
    reader_fixture_t fixture;
    begin(&fixture, 4096, 16384, VMESS_SECURITY_NONE, VMESS_OPTION_CHUNK);
    uint8_t wire[256];
    size_t  length = seal(&fixture, wire, true);
    append(&fixture, wire, length);
    vmess_record_result_t result = readRecord(&fixture);
    require(result.status == kVmessRecordEof && result.payload == NULL && result.consumed == 2 &&
                fixture.budget.used.bytes == 0 && fixture.budget.used.charge == 0,
            "zero-body framed NONE termination did not finish in the prefix call");
    end(&fixture);
}

int main(void)
{
    testCaseSet("vmess_record_reader_test");
    require(wCryptoGlobalInit() == kWCryptoOk, "crypto initialization failed");
    for (size_t i = 0; i < ARRAY_SIZE(masters); ++i)
        masters[i] = masterpoolCreateWithCapacity(8);
    pool = bufferpoolCreate(masters[0], masters[1], masters[2], 2, 4096, 1024, 256, 4096, 4096);
    require(pool != NULL, "reader pool construction failed");
    bufferpoolUpdateAllocationPaddings(pool, 96, 32, 32, 32);
    TEST_RUN_CASE(testFragmentedRecord);
    TEST_RUN_CASE(testPartialCleanup);
    TEST_RUN_CASE(testAllocationLimit);
    TEST_RUN_CASE(testCoalescedRecords);
    TEST_RUN_CASE(testTerminalRecords);
    bufferpoolDestroy(pool);
    for (size_t i = 0; i < ARRAY_SIZE(masters); ++i)
    {
        masterpoolMakeEmpty(masters[i]);
        masterpoolDestroy(masters[i]);
    }
    wCryptoGlobalCleanup();
    return 0;
}
