/* CTest: waterwall.enet_settings_unit.
 * The settings shared by EnetClient and EnetServer: defaults, the send-mtu to host-MTU conversion with its cap,
 * every range boundary, wrong JSON types, the ping/timeout relation, and an inherited core MTU that ENet cannot
 * use. Runs inside an initialized worker runtime because the default send-mtu comes from the core settings. */

#include "EnetCommon/settings.h"

#include "enet_runtime.h"

static bool parse(const char *json, enet_settings_t *settings)
{
    cJSON *object = cJSON_Parse(json);
    enetRequire(object != NULL, "fixture JSON failed to parse");
    const bool accepted = enetSettingsParse(settings, object, "EnetTest");
    cJSON_Delete(object);
    return accepted;
}

static void testDefaults(void)
{
    enet_settings_t settings;
    enetRequire(parse("{}", &settings), "empty settings were refused");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.send_mtu, 1500, "send-mtu does not inherit the core MTU");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.host_mtu, 1472, "host MTU is not send-mtu minus 28");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.ping_interval_ms, 10000, "ping-interval-ms default changed");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.no_recv_timeout_ms, 30000, "no-recv-timeout-ms default changed");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.send_buffer_limit, 524288, "send-buffer-limit default changed");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.receive_buffer_limit, 1048576, "receive-buffer-limit default changed");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.carrier_queue_limit, 256, "carrier-queue-limit default changed");
    TEST_EQUAL_UINT(
        TEST_FAILURE_EXIT, settings.close_drain_timeout_ms, 30000, "close-drain-timeout-ms default changed");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.incoming_bandwidth, 0, "incoming-bandwidth default changed");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.outgoing_bandwidth, 0, "outgoing-bandwidth default changed");

    enet_settings_t missing;
    enetRequire(enetSettingsParse(&missing, NULL, "EnetTest"), "a node without a settings object was refused");
    enetRequire(missing.send_mtu == 1500 && missing.host_mtu == 1472 && missing.carrier_queue_limit == 256,
                "a missing settings object does not give the defaults");
}

static void testSendMtu(void)
{
    static const struct
    {
        const char *json;
        uint16_t    send_mtu;
        uint32_t    host_mtu;
    } valid[] = {
        {"{\"send-mtu\":604}", 604, 576},
        {"{\"send-mtu\":1420}", 1420, 1392},
        {"{\"send-mtu\":4124}", 4124, 4096},
        {"{\"send-mtu\":4125}", 4125, 4096},
        {"{\"send-mtu\":65535}", 65535, 4096},
    };
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i)
    {
        enet_settings_t settings;
        enetRequire(parse(valid[i].json, &settings), "a valid send-mtu was refused");
        TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.send_mtu, valid[i].send_mtu, "send-mtu was not stored");
        TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.host_mtu, valid[i].host_mtu, "host MTU conversion is wrong");
    }
    static const char *invalid[] = {
        "{\"send-mtu\":603}",
        "{\"send-mtu\":65536}",
        "{\"send-mtu\":-1}",
        "{\"send-mtu\":\"1500\"}",
        "{\"send-mtu\":1500.5}",
        "{\"send-mtu\":null}",
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        enet_settings_t settings;
        enetRequire(! parse(invalid[i], &settings), "an invalid send-mtu was accepted");
    }
}

static void testInheritedMtu(void)
{
    const uint16_t  saved = GSTATE.mtu_size;
    enet_settings_t settings;
    GSTATE.mtu_size = 600;
    enetRequire(! parse("{}", &settings), "an inherited core MTU below ENet's minimum was accepted");
    enetRequire(parse("{\"send-mtu\":1400}", &settings) && settings.host_mtu == 1372,
                "an explicit send-mtu did not override an unusable core MTU");
    GSTATE.mtu_size = 9000;
    enetRequire(parse("{}", &settings) && settings.send_mtu == 9000 && settings.host_mtu == 4096,
                "an inherited core MTU above ENet's maximum was not capped");
    GSTATE.mtu_size = saved;
}

static void testRanges(void)
{
    static const char *invalid[] = {
        "{\"no-recv-timeout-ms\":0}",
        "{\"no-recv-timeout-ms\":2147483648}",
        "{\"ping-interval-ms\":0}",
        "{\"ping-interval-ms\":30000}",  /* equal to the default timeout */
        "{\"no-recv-timeout-ms\":5000}", /* below the default ping interval */
        "{\"send-buffer-limit\":4095}",
        "{\"send-buffer-limit\":134217729}",
        "{\"receive-buffer-limit\":131071}",
        "{\"receive-buffer-limit\":268435457}",
        "{\"carrier-queue-limit\":0}",
        "{\"carrier-queue-limit\":65536}",
        "{\"close-drain-timeout-ms\":0}",
        "{\"close-drain-timeout-ms\":2147483648}",
        "{\"incoming-bandwidth\":-1}",
        "{\"outgoing-bandwidth\":4294967296}",
        "{\"send-buffer-limit\":true}",
        "{\"carrier-queue-limit\":\"256\"}",
        "{\"close-drain-timeout-ms\":1.5}",
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        enet_settings_t settings;
        enetRequire(! parse(invalid[i], &settings), "an out-of-range or mistyped setting was accepted");
    }

    enet_settings_t low;
    enetRequire(parse("{\"no-recv-timeout-ms\":2,\"ping-interval-ms\":1,\"send-buffer-limit\":4096,"
                      "\"receive-buffer-limit\":131072,\"carrier-queue-limit\":1,\"close-drain-timeout-ms\":1,"
                      "\"incoming-bandwidth\":0,\"outgoing-bandwidth\":0}",
                      &low),
                "the lowest valid values were refused");
    enetRequire(low.no_recv_timeout_ms == 2 && low.ping_interval_ms == 1 && low.send_buffer_limit == 4096 &&
                    low.receive_buffer_limit == 131072 && low.carrier_queue_limit == 1 &&
                    low.close_drain_timeout_ms == 1,
                "the lowest valid values were not stored");

    enet_settings_t high;
    enetRequire(parse("{\"no-recv-timeout-ms\":2147483647,\"ping-interval-ms\":2147483646,"
                      "\"send-buffer-limit\":134217728,\"receive-buffer-limit\":268435456,"
                      "\"carrier-queue-limit\":65535,\"close-drain-timeout-ms\":2147483647,"
                      "\"incoming-bandwidth\":4294967295,\"outgoing-bandwidth\":4294967295}",
                      &high),
                "the highest valid values were refused");
    enetRequire(high.no_recv_timeout_ms == 2147483647U && high.ping_interval_ms == 2147483646U &&
                    high.send_buffer_limit == 134217728U && high.receive_buffer_limit == 268435456U &&
                    high.carrier_queue_limit == 65535U && high.close_drain_timeout_ms == 2147483647U &&
                    high.incoming_bandwidth == 4294967295U && high.outgoing_bandwidth == 4294967295U,
                "the highest valid values were not stored");
}

int main(void)
{
    enetRuntimeStart();
    TEST_RUN_CASE(testDefaults);
    TEST_RUN_CASE(testSendMtu);
    TEST_RUN_CASE(testInheritedMtu);
    TEST_RUN_CASE(testRanges);
    enetRuntimeStop();
    return 0;
}
