/* CTest: waterwall.gns_settings_unit.
 * The settings shared by GnsClient and GnsServer: defaults, the send-mtu to packet-size conversion with its cap,
 * every range boundary, wrong JSON types, an inherited core MTU that GNS cannot use, and the values derived for
 * GNS's 16-bit limits. Runs inside an initialized worker runtime because the default send-mtu comes from the core
 * settings. */

#include "GnsCommon/settings.h"

#include "gns_runtime.h"

static bool parse(const char *json, gns_settings_t *settings)
{
    cJSON *object = cJSON_Parse(json);
    gnsRequire(object != NULL, "fixture JSON failed to parse");
    const bool accepted = gnsSettingsParse(settings, object, "GnsTest");
    cJSON_Delete(object);
    return accepted;
}

static void testDefaults(void)
{
    gns_settings_t settings;
    gnsRequire(parse("{}", &settings), "empty settings were refused");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.send_mtu, 1500, "send-mtu does not inherit the core MTU");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.packet_size, 1300, "packet size is not capped at GNS's maximum");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.no_recv_timeout_ms, 30000, "no-recv-timeout-ms default changed");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.timeout_initial_ms, 10000, "timeout-initial-ms default changed");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.send_rate, 262144, "send-rate default changed");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.send_buffer_limit, 524288, "send-buffer-limit default changed");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.send_hard_limit, 1048576, "the hard limit is not twice the hold");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.receive_buffer_limit, 1048576, "receive-buffer-limit default changed");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.receive_messages_limit, 4096, "message limit is not bytes / 256");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.carrier_queue_limit, 256, "carrier-queue-limit default changed");
    TEST_EQUAL_UINT(
        TEST_FAILURE_EXIT, settings.close_drain_timeout_ms, 30000, "close-drain-timeout-ms default changed");

    gns_settings_t missing;
    gnsRequire(gnsSettingsParse(&missing, NULL, "GnsTest"), "a node without a settings object was refused");
    gnsRequire(missing.send_mtu == 1500 && missing.packet_size == 1300 && missing.send_rate == 262144,
               "a missing settings object does not give the defaults");
}

static void testSendMtu(void)
{
    static const struct
    {
        const char *json;
        uint16_t    send_mtu;
        uint32_t    packet_size;
    } valid[] = {
        {"{\"send-mtu\":228}", 228, 200},
        {"{\"send-mtu\":1280}", 1280, 1252},
        {"{\"send-mtu\":1328}", 1328, 1300},
        {"{\"send-mtu\":1329}", 1329, 1300},
        {"{\"send-mtu\":65535}", 65535, 1300},
    };
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i)
    {
        gns_settings_t settings;
        gnsRequire(parse(valid[i].json, &settings), "a valid send-mtu was refused");
        TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.send_mtu, valid[i].send_mtu, "send-mtu was not stored");
        TEST_EQUAL_UINT(
            TEST_FAILURE_EXIT, settings.packet_size, valid[i].packet_size, "packet size conversion is wrong");
    }
    static const char *invalid[] = {
        "{\"send-mtu\":227}",
        "{\"send-mtu\":65536}",
        "{\"send-mtu\":-1}",
        "{\"send-mtu\":\"1500\"}",
        "{\"send-mtu\":1500.5}",
        "{\"send-mtu\":null}",
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        gns_settings_t settings;
        gnsRequire(! parse(invalid[i], &settings), "an invalid send-mtu was accepted");
    }
}

static void testInheritedMtu(void)
{
    const uint16_t saved = GSTATE.mtu_size;
    gns_settings_t settings;
    GSTATE.mtu_size = 200;
    gnsRequire(! parse("{}", &settings), "an inherited core MTU below GNS's minimum was accepted");
    gnsRequire(parse("{\"send-mtu\":1400}", &settings) && settings.packet_size == 1300,
               "an explicit send-mtu did not override an unusable core MTU");
    GSTATE.mtu_size = 9000;
    gnsRequire(parse("{}", &settings) && settings.send_mtu == 9000 && settings.packet_size == 1300,
               "an inherited core MTU above GNS's maximum was not capped");
    GSTATE.mtu_size = saved;
}

static void testRanges(void)
{
    static const char *invalid[] = {
        "{\"no-recv-timeout-ms\":0}",
        "{\"no-recv-timeout-ms\":2147483648}",
        "{\"timeout-initial-ms\":0}",
        "{\"timeout-initial-ms\":2147483648}",
        "{\"send-rate\":1023}",
        "{\"send-rate\":104857601}",
        "{\"send-buffer-limit\":4095}",
        "{\"send-buffer-limit\":134217729}",
        "{\"receive-buffer-limit\":131071}",
        "{\"receive-buffer-limit\":268435457}",
        "{\"carrier-queue-limit\":0}",
        "{\"carrier-queue-limit\":65536}",
        "{\"close-drain-timeout-ms\":0}",
        "{\"close-drain-timeout-ms\":2147483648}",
        "{\"send-rate\":true}",
        "{\"carrier-queue-limit\":\"256\"}",
        "{\"close-drain-timeout-ms\":1.5}",
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        gns_settings_t settings;
        gnsRequire(! parse(invalid[i], &settings), "an out-of-range or mistyped setting was accepted");
    }

    gns_settings_t low;
    gnsRequire(parse("{\"no-recv-timeout-ms\":1,\"timeout-initial-ms\":1,\"send-rate\":1024,"
                     "\"send-buffer-limit\":4096,\"receive-buffer-limit\":131072,\"carrier-queue-limit\":1,"
                     "\"close-drain-timeout-ms\":1}",
                     &low),
               "the lowest valid values were refused");
    gnsRequire(low.no_recv_timeout_ms == 1 && low.timeout_initial_ms == 1 && low.send_rate == 1024 &&
                   low.send_buffer_limit == 4096 && low.send_hard_limit == 8192 && low.receive_buffer_limit == 131072 &&
                   low.receive_messages_limit == 1000 && low.carrier_queue_limit == 1 &&
                   low.close_drain_timeout_ms == 1,
               "the lowest valid values were not stored");

    gns_settings_t high;
    gnsRequire(parse("{\"no-recv-timeout-ms\":2147483647,\"timeout-initial-ms\":2147483647,"
                     "\"send-rate\":104857600,\"receive-buffer-limit\":268435456,\"carrier-queue-limit\":65535,"
                     "\"close-drain-timeout-ms\":2147483647}",
                     &high),
               "the highest valid values were refused");
    gnsRequire(high.no_recv_timeout_ms == 2147483647U && high.timeout_initial_ms == 2147483647U &&
                   high.send_rate == 104857600U && high.receive_buffer_limit == 268435456U &&
                   high.receive_messages_limit == 1048576U && high.carrier_queue_limit == 65535U &&
                   high.close_drain_timeout_ms == 2147483647U,
               "the highest valid values were not stored");
}

/* GNS can keep 16,000 packets' worth of data apart. A larger send-buffer-limit is valid and uses that. */
static void testPacketWindow(void)
{
    gns_settings_t settings;
    gnsRequire(parse("{\"send-buffer-limit\":134217728}", &settings), "the largest send-buffer-limit was refused");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.send_hard_limit, 16000U * 1200U, "the hard limit ignores the window");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.send_buffer_limit, 8000U * 1200U, "the hold is not half the limit");

    gnsRequire(parse("{\"send-mtu\":228,\"send-buffer-limit\":1000000}", &settings), "small packets were refused");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.send_hard_limit, 16000U * 100U, "small packets: wrong hard limit");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.send_buffer_limit, 8000U * 100U, "small packets: wrong hold");

    gnsRequire(parse("{\"send-mtu\":228}", &settings), "small packets with the default buffer were refused");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.send_buffer_limit, 524288, "a hold inside the window was changed");
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, settings.send_hard_limit, 1048576, "a limit inside the window was changed");
}

int main(void)
{
    gnsTestRuntimeStart();
    TEST_RUN_CASE(testDefaults);
    TEST_RUN_CASE(testSendMtu);
    TEST_RUN_CASE(testInheritedMtu);
    TEST_RUN_CASE(testRanges);
    TEST_RUN_CASE(testPacketWindow);
    gnsTestRuntimeStop();
    return 0;
}
