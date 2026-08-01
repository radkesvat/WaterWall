#include "TlsRecordShapingCommon/record_shaping.h"
#include "wwapi.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static cJSON *parseObject(const char *text)
{
    cJSON *object = cJSON_Parse(text);
    require(object != NULL && cJSON_IsObject(object), "test JSON did not parse as an object");
    return object;
}

static tlsrecordshaping_config_t parseValid(const char *text)
{
    cJSON                    *settings = parseObject(text);
    tlsrecordshaping_config_t config   = {0};
    char                      error[kTlsRecordShapingErrorSize];
    require(tlsrecordshapingParse(settings, kTlsRecordShapingSenderClient, &config, error), error);
    cJSON_Delete(settings);
    return config;
}

static void requireInvalid(const char *text)
{
    cJSON                    *settings = parseObject(text);
    tlsrecordshaping_config_t config   = {0};
    char                      error[kTlsRecordShapingErrorSize];
    require(! tlsrecordshapingParse(settings, kTlsRecordShapingSenderServer, &config, error),
            "invalid shaping configuration was accepted");
    require(error[0] != '\0', "invalid shaping configuration returned no diagnostic");
    cJSON_Delete(settings);
}

static const char kCustom[] = "{\"tls13-record-shaping\":{"
                              "\"scope\":{\"first-application-records\":8},"
                              "\"outcomes\":["
                              "{\"probability\":50,\"padding-bytes\":[100,200],"
                              "\"delay\":{\"probability\":75,\"ms\":[10,20]}},"
                              "{\"probability\":10,\"padding-bytes\":500}]}}";

static void testAbsentAndNormalization(void)
{
    tlsrecordshaping_config_t disabled = parseValid("{}");
    require(! disabled.enabled, "absent shaping setting was not disabled");

    tlsrecordshaping_config_t config = parseValid(kCustom);
    require(config.enabled, "custom configuration mode was not preserved");
    require(config.first_application_records == 8 && config.outcome_count == 2,
            "custom scope or outcome count changed");
    require(config.outcomes[0].padding_bytes.minimum == 100 && config.outcomes[0].padding_bytes.maximum == 200,
            "padding range did not normalize");
    require(config.outcomes[1].padding_bytes.minimum == 500 && config.outcomes[1].padding_bytes.maximum == 500,
            "scalar padding did not normalize to an inclusive fixed range");
    require(config.outcomes[0].delay_ms.minimum == 10 && config.outcomes[0].delay_ms.maximum == 20,
            "delay range did not normalize");
}

static void testDeterministicBoundariesAndScope(void)
{
    tlsrecordshaping_config_t   config = parseValid(kCustom);
    tlsrecordshaping_state_t    state  = {0};
    tlsrecordshaping_decision_t decision;

    require(tlsrecordshapingSelectDeterministic(&config, &state, 1, 100, 1, 10, &decision),
            "inclusive minimum selection failed");
    require(decision.outcome_selected && decision.selected_outcome == 0 && decision.requested_padding_bytes == 100 &&
                decision.delay_ms == 10,
            "inclusive minimum draw selected the wrong values");

    require(tlsrecordshapingSelectDeterministic(&config, &state, 50, 200, 75, 20, &decision),
            "first probability upper boundary failed");
    require(decision.selected_outcome == 0 && decision.requested_padding_bytes == 200 && decision.delay_ms == 20,
            "inclusive maximum draw selected the wrong values");

    require(tlsrecordshapingSelectDeterministic(&config, &state, 51, 500, 1, 0, &decision),
            "second outcome lower boundary failed");
    require(decision.selected_outcome == 1 && decision.requested_padding_bytes == 500,
            "roll 51 did not select the second outcome");

    require(tlsrecordshapingSelectDeterministic(&config, &state, 60, 500, 1, 0, &decision),
            "second outcome upper boundary failed");
    require(decision.selected_outcome == 1, "roll 60 did not select the second outcome");

    require(tlsrecordshapingSelectDeterministic(&config, &state, 61, 0, 1, 0, &decision),
            "unassigned probability selection failed");
    require(decision.considered && ! decision.outcome_selected,
            "unassigned probability did not produce an eligible no-op");

    require(tlsrecordshapingSelectDeterministic(&config, &state, 1, 150, 76, 15, &decision),
            "conditional delay selection failed");
    require(decision.requested_padding_bytes == 150 && decision.delay_ms == 0,
            "delay probability was not evaluated conditionally");

    while (state.application_records_seen < config.first_application_records)
    {
        require(tlsrecordshapingSelectDeterministic(&config, &state, 100, 0, 100, 0, &decision),
                "scope no-op selection failed");
        require(decision.considered && ! decision.outcome_selected, "scope no-op did not consume eligibility");
    }
    require(tlsrecordshapingSelectDeterministic(&config, &state, 1, 100, 1, 10, &decision),
            "scope exhaustion returned an internal error");
    require(! decision.considered && state.application_records_seen == config.first_application_records,
            "scope exhaustion still sampled an application record");
}

static void testInvalidConfigurations(void)
{
    static const char *const invalid[] = {
        "{\"tls13-record-shaping\":\"experimental-balanced-v1\"}",
        "{\"tls13-record-shaping\":{}}",
        "{\"tls13-record-shaping\":{\"profile\":\"experimental-balanced-v1\"}}",
        "{\"tls13-record-shaping\":{\"profile\":\"unknown\"}}",
        "{\"tls13-record-shaping\":{\"profile\":\"experimental-balanced-v1\",\"outcomes\":[]}}",
        "{\"tls13-record-shaping\":{\"typo\":1}}",
        "{\"tls13-record-shaping\":{\"scope\":{\"first-application-records\":1,\"typo\":1},\"outcomes\":[{"
        "\"probability\":1,\"padding-bytes\":1}]}}",
        "{\"tls13-record-shaping\":{\"scope\":{\"first-application-records\":0},\"outcomes\":[{\"probability\":1,"
        "\"padding-bytes\":1}]}}",
        "{\"tls13-record-shaping\":{\"scope\":{\"first-application-records\":1025},\"outcomes\":[{\"probability\":1,"
        "\"padding-bytes\":1}]}}",
        "{\"tls13-record-shaping\":{\"scope\":{\"first-application-records\":1.5},\"outcomes\":[{\"probability\":1,"
        "\"padding-bytes\":1}]}}",
        "{\"tls13-record-shaping\":{\"scope\":{\"first-application-records\":1},\"outcomes\":[]}}",
        "{\"tls13-record-shaping\":{\"scope\":{\"first-application-records\":1},\"outcomes\":[{\"probability\":0,"
        "\"padding-bytes\":1}]}}",
        "{\"tls13-record-shaping\":{\"scope\":{\"first-application-records\":1},\"outcomes\":[{\"probability\":101,"
        "\"padding-bytes\":1}]}}",
        "{\"tls13-record-shaping\":{\"scope\":{\"first-application-records\":1},\"outcomes\":[{\"probability\":60,"
        "\"padding-bytes\":1},{\"probability\":41,\"padding-bytes\":1}]}}",
        "{\"tls13-record-shaping\":{\"scope\":{\"first-application-records\":1},\"outcomes\":[{\"probability\":1}]}}",
        "{\"tls13-record-shaping\":{\"scope\":{\"first-application-records\":1},\"outcomes\":[{\"probability\":1,"
        "\"padding-bytes\":0}]}}",
        "{\"tls13-record-shaping\":{\"scope\":{\"first-application-records\":1},\"outcomes\":[{\"probability\":1,"
        "\"padding-bytes\":4097}]}}",
        "{\"tls13-record-shaping\":{\"scope\":{\"first-application-records\":1},\"outcomes\":[{\"probability\":1,"
        "\"padding-bytes\":[2,1]}]}}",
        "{\"tls13-record-shaping\":{\"scope\":{\"first-application-records\":1},\"outcomes\":[{\"probability\":1,"
        "\"padding-bytes\":[1]}]}}",
        "{\"tls13-record-shaping\":{\"scope\":{\"first-application-records\":1},\"outcomes\":[{\"probability\":1,"
        "\"padding-bytes\":1.25}]}}",
        "{\"tls13-record-shaping\":{\"scope\":{\"first-application-records\":1},\"outcomes\":[{\"probability\":1,"
        "\"padding-bytes\":-1}]}}",
        "{\"tls13-record-shaping\":{\"scope\":{\"first-application-records\":1},\"outcomes\":[{\"probability\":1,"
        "\"padding-bytes\":1e100}]}}",
        "{\"tls13-record-shaping\":{\"scope\":{\"first-application-records\":1},\"outcomes\":[{\"probability\":1,"
        "\"delay\":{\"probability\":50,\"ms\":0}}]}}",
        "{\"tls13-record-shaping\":{\"scope\":{\"first-application-records\":1},\"outcomes\":[{\"probability\":1,"
        "\"padding-bytes\":1,\"typo\":1}]}}",
        "{\"tls13-record-shaping\":{\"scope\":{\"first-application-records\":1},\"outcomes\":[{\"probability\":1,"
        "\"delay\":{\"probability\":101,\"ms\":1}}]}}",
        "{\"tls13-record-shaping\":{\"scope\":{\"first-application-records\":1},\"outcomes\":[{\"probability\":1,"
        "\"delay\":{\"probability\":50,\"ms\":1001}}]}}",
        "{\"tls13-record-shaping\":{\"scope\":{\"first-application-records\":1},\"outcomes\":[{\"probability\":1,"
        "\"delay\":{\"probability\":50,\"ms\":1,\"typo\":1}}]}}",
    };

    for (size_t i = 0; i < ARRAY_SIZE(invalid); ++i)
    {
        requireInvalid(invalid[i]);
    }
}

typedef struct shaping_pool_s
{
    master_pool_t *large_master;
    master_pool_t *small_master;
    buffer_pool_t *pool;
} shaping_pool_t;

static shaping_pool_t createPool(void)
{
    shaping_pool_t result = {0};
    result.large_master   = masterpoolCreateWithCapacity(8);
    result.small_master   = masterpoolCreateWithCapacity(8);
    result.pool           = bufferpoolCreate(result.large_master, result.small_master, 4, 32768, 1024);
    require(result.large_master != NULL && result.small_master != NULL && result.pool != NULL,
            "failed to create shaping output test pool");
    bufferpoolUpdateAllocationPaddings(result.pool, 64, 64);
    return result;
}

static void destroyPool(shaping_pool_t *pool)
{
    bufferpoolDestroy(pool->pool);
    masterpoolMakeEmpty(pool->large_master);
    masterpoolMakeEmpty(pool->small_master);
    masterpoolDestroy(pool->large_master);
    masterpoolDestroy(pool->small_master);
}

static size_t appendRecord(uint8_t *destination, size_t body_length, uint8_t fill)
{
    destination[0] = 0x17;
    destination[1] = 0x03;
    destination[2] = 0x03;
    destination[3] = (uint8_t) (body_length >> 8U);
    destination[4] = (uint8_t) body_length;
    memorySet(destination + kTlsRecordShapingRecordHeaderSize, fill, body_length);
    return kTlsRecordShapingRecordHeaderSize + body_length;
}

static sbuf_t *makeBuffer(buffer_pool_t *pool, const uint8_t *bytes, size_t length)
{
    sbuf_t *buffer = bufferpoolGetLargeBuffer(pool);
    require(length <= sbufGetMaximumWriteableSize(buffer), "shaping test buffer was too small");
    memoryCopy(sbufGetMutablePtr(buffer), bytes, length);
    sbufSetLength(buffer, (uint32_t) length);
    return buffer;
}

static void testOutputFramingAndDeadlines(void)
{
    shaping_pool_t                  pool = createPool();
    tlsrecordshaping_output_queue_t queue;
    tlsrecordshapingOutputQueueInitialize(&queue, pool.pool);

    uint8_t wire[64];
    size_t  first_length  = appendRecord(wire, 7, 0x11);
    size_t  second_length = appendRecord(wire + first_length, 9, 0x22);
    size_t  total_length  = first_length + second_length;

    require(tlsrecordshapingOutputQueuePushPendingMetadata(&queue, 20) &&
                tlsrecordshapingOutputQueueHasPendingMetadata(&queue) &&
                tlsrecordshapingOutputQueueCommitMetadata(&queue, 0) &&
                tlsrecordshapingOutputQueuePushMetadata(&queue, 5),
            "failed to enqueue deterministic shaping metadata");

    char error[kTlsRecordShapingErrorSize];
    require(tlsrecordshapingOutputQueueFeed(&queue, makeBuffer(pool.pool, wire, 3), 100, error), error);
    require(tlsrecordshapingOutputQueueCount(&queue) == 0, "partial TLS header was treated as a complete record");
    require(tlsrecordshapingOutputQueueFeed(&queue, makeBuffer(pool.pool, wire + 3, total_length - 3), 100, error),
            error);
    require(tlsrecordshapingOutputQueueFinishFeed(&queue, error), error);
    require(tlsrecordshapingOutputQueueCount(&queue) == 2 && tlsrecordshapingOutputQueueBytes(&queue) == total_length,
            "fragmented/coalesced records were not split into the FIFO");

    require(tlsrecordshapingOutputQueuePopReady(&queue, 119, false) == NULL,
            "first record was released before its deadline");
    sbuf_t *first  = tlsrecordshapingOutputQueuePopReady(&queue, 120, false);
    sbuf_t *second = tlsrecordshapingOutputQueuePopReady(&queue, 120, false);
    require(first != NULL && second != NULL && sbufGetLength(first) == first_length &&
                sbufGetLength(second) == second_length,
            "equalized FIFO deadlines did not drain both ready records in order");
    bufferpoolReuseBuffer(pool.pool, first);
    bufferpoolReuseBuffer(pool.pool, second);
    require(tlsrecordshapingOutputQueueIsEmpty(&queue), "drained output queue did not become empty");

    tlsrecordshapingOutputQueueDestroy(&queue);
    destroyPool(&pool);
}

static void testOutputMetadataMismatch(void)
{
    shaping_pool_t                  pool = createPool();
    tlsrecordshaping_output_queue_t queue;
    tlsrecordshapingOutputQueueInitialize(&queue, pool.pool);

    uint8_t wire[16];
    size_t  length = appendRecord(wire, 4, 0x33);
    char    error[kTlsRecordShapingErrorSize];
    require(! tlsrecordshapingOutputQueueFeed(&queue, makeBuffer(pool.pool, wire, length), 0, error),
            "complete TLS record without metadata was accepted");
    require(strstr(error, "no matching shaping decision") != NULL, "metadata mismatch returned an unstable diagnostic");

    tlsrecordshapingOutputQueueDestroy(&queue);
    destroyPool(&pool);
}

int main(void)
{
    testAbsentAndNormalization();
    testDeterministicBoundariesAndScope();
    testInvalidConfigurations();
    testOutputFramingAndDeadlines();
    testOutputMetadataMismatch();
    return 0;
}
