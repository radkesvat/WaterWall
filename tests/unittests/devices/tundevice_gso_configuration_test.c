/*
 * Covers: TunDevice GSO, multiqueue and kernel queue settings, including defaults, strict types and independence.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Cases: testSettings
 * Checks: Both requests retain their own default/value; invalid settings reject construction;
 * TUN must certify enqueue-only Payload.
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.tundevice_gso_configuration_unit
 */
#include "TunDevice/interface.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)
#include "TunDevice/structure.h"

#include "loggers/network_logger.h"

#include <limits.h>

static void testSettings(const char *gso_value, const char *multi_queue_value, bool valid, bool expected_gso,
                         bool expected_multi_queue)
{
    cJSON *settings =
        cJSON_Parse("{\"device-name\":\"ww-fixture\",\"device-ip\":\"192.0.2.1/24\",\"device-mtu\":1500}");
    require(settings != NULL, "cannot parse TunDevice settings fixture");

    const char *keys[]   = {"gso", "multi-queue"};
    const char *values[] = {gso_value, multi_queue_value};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i)
    {
        if (values[i] != NULL)
        {
            cJSON *value = cJSON_Parse(values[i]);
            require(value != NULL, "cannot parse TunDevice boolean value fixture");
            require(cJSON_AddItemToObject(settings, keys[i], value), "cannot add TunDevice boolean value fixture");
        }
    }

    node_t    node   = {.node_settings_json = settings};
    tunnel_t *tunnel = tundeviceTunnelCreate(&node);
    require((tunnel != NULL) == valid, "TunDevice boolean setting accepted or rejected incorrectly");
    if (tunnel != NULL)
    {
        tundevice_tstate_t *state = tunnelGetState(tunnel);
        require(state->gso_requested == expected_gso, "GSO setting had the wrong default or value");
        require(state->multi_queue_requested == expected_multi_queue,
                "multiqueue setting had the wrong default or value");
        tundeviceTunnelDestroy(tunnel, wwLifecycleStartupRollback());
    }
    cJSON_Delete(settings);
}

static void testKernelQueueSettings(const char *tune_value, const char *length_value, bool valid, bool expected_tune,
                                    uint32_t expected_length)
{
    cJSON *settings =
        cJSON_Parse("{\"device-name\":\"ww-fixture\",\"device-ip\":\"192.0.2.1/24\",\"device-mtu\":1500}");
    require(settings != NULL, "cannot parse kernel queue settings fixture");
    const char *keys[]   = {"kernel-queue-tune", "kernel-queue-length"};
    const char *values[] = {tune_value, length_value};
    for (size_t i = 0; i < ARRAY_SIZE(keys); ++i)
    {
        if (values[i] == NULL)
            continue;
        cJSON *value = cJSON_Parse(values[i]);
        require(value != NULL && cJSON_AddItemToObject(settings, keys[i], value), "invalid kernel queue fixture");
    }
    node_t    node   = {.node_settings_json = settings};
    tunnel_t *tunnel = tundeviceTunnelCreate(&node);
    require((tunnel != NULL) == valid, "kernel queue settings accepted or rejected incorrectly");
    if (tunnel != NULL)
    {
        tundevice_tstate_t *state = tunnelGetState(tunnel);
        require(state->kernel_queue_tune == expected_tune && state->kernel_queue_length == expected_length,
                "kernel queue defaults or explicit settings changed");
        tundeviceTunnelDestroy(tunnel, wwLifecycleStartupRollback());
    }
    cJSON_Delete(settings);
}

int main(void)
{
    testCaseSet("tundevice_gso_configuration_test");
    logger_t *logger = loggerCreate();
    require(logger != NULL, "logger allocation failed");
    setNetworkLogger(logger);

    node_t metadata = nodeTunDeviceGet();
    require((metadata.flags & kNodeFlagPacketPayloadEnqueueOnly) != 0, "TUN must certify enqueue-only Payload");
    require(metadata.required_padding_left == kTunVirtioHeaderSize, "Linux TUN headroom does not fit virtio header");
    require((metadata.flags & kNodeFlagSupportsTrustedPacketChecksums) != 0 &&
                (metadata.flags &
                 (kNodeFlagTrustedPacketChecksumsActive | kNodeFlagTrustedPacketReceiveChecksumsActive)) == 0,
            "template must advertise capability without activating it");
    node_t   peer   = {.flags = kNodeFlagSupportsTrustedPacketChecksums, .layer_group = kNodeLayer3 | kNodeLayer4};
    node_t   other  = {.flags = kNodeFlagSupportsTrustedPacketChecksums};
    node_t   middle = {.flags = kNodeFlagNone};
    tunnel_t tun = {.node = &metadata}, ptc = {.node = &peer}, interposed = {.node = &middle}, spare = {.node = &other};
    require(! packettunnelTrustedChecksumPairEligible(&tun, NULL), "missing peer eligible");
    tun.next = &ptc;
    require(! packettunnelTrustedChecksumPairEligible(&tun, &ptc), "one-sided link eligible");
    ptc.prev = &tun;
    require(packettunnelTrustedChecksumPairEligible(&tun, &ptc), "direct pair refused");
    peer.layer_group = kNodeLayer3;
    require(! packettunnelTrustedChecksumPairEligible(&tun, &ptc), "two TUN nodes negotiated a bridge contract");
    peer.layer_group = kNodeLayer3 | kNodeLayer4;
    require(! packettunnelTrustedChecksumPairEligible(&ptc, &tun), "reverse edge eligible");
    tun.next        = &interposed;
    interposed.prev = &tun;
    interposed.next = &ptc;
    ptc.prev        = &interposed;
    require(! packettunnelTrustedChecksumPairEligible(&tun, &ptc) &&
                ! packettunnelTrustedChecksumPairEligible(&tun, &interposed),
            "interposed node inherited trust");
    tun.next = &ptc;
    ptc.prev = &tun;
    packettunnelActivateTrustedChecksumPair(&tun, &ptc);
    require(packettunnelTrustedChecksumsActive(&tun) && packettunnelTrustedChecksumsActive(&ptc) &&
                ! packettunnelTrustedChecksumsActive(&spare),
            "pair mode escaped to another instance");
    require(packettunnelTrustedReceiveChecksumsActive(&tun) && packettunnelTrustedReceiveChecksumsActive(&ptc),
            "negotiated checksum mode did not retain receive trust");
    metadata.flags &= ~kNodeFlagTrustedPacketChecksumsActive;
    peer.flags &= ~kNodeFlagTrustedPacketChecksumsActive;
    packettunnelActivateTrustedReceiveChecksumPair(&tun, &ptc);
    require(packettunnelTrustedReceiveChecksumsActive(&tun) && packettunnelTrustedReceiveChecksumsActive(&ptc) &&
                ! packettunnelTrustedReceiveChecksumsActive(&spare),
            "receive-only pair mode escaped to another instance");
    require(! packettunnelTrustedChecksumsActive(&tun) && ! packettunnelTrustedChecksumsActive(&ptc),
            "receive-only pair activated partial transmit checksums");
    require((metadata.flags & (kNodeFlagChainHead | kNodeFlagChainEnd)) == (kNodeFlagChainHead | kNodeFlagChainEnd),
            "activation overwrote other node flags");
    memoryFree(metadata.type);

    testSettings(NULL, NULL, true, true, true);
    testSettings("true", NULL, true, true, true);
    testSettings("false", NULL, true, false, true);
    testSettings(NULL, "true", true, true, true);
    testSettings(NULL, "false", true, true, false);
    for (unsigned gso = 0; gso < 2; ++gso)
    {
        for (unsigned multi_queue = 0; multi_queue < 2; ++multi_queue)
        {
            testSettings(gso ? "true" : "false", multi_queue ? "true" : "false", true, gso, multi_queue);
        }
    }
    const char *invalid_values[] = {"null", "0", "1", "\"true\"", "[]", "{}"};
    for (size_t i = 0; i < sizeof(invalid_values) / sizeof(invalid_values[0]); ++i)
    {
        testSettings(invalid_values[i], NULL, false, false, false);
        testSettings(NULL, invalid_values[i], false, false, false);
        testKernelQueueSettings(invalid_values[i], NULL, false, false, 0);
    }

    testKernelQueueSettings(NULL, NULL, true, true, 0);
    testKernelQueueSettings("true", "1", true, true, 1);
    testKernelQueueSettings("false", NULL, true, false, 0);
    testKernelQueueSettings("false", "8192", true, false, 8192);
    testKernelQueueSettings(NULL, "2147483647", true, true, INT_MAX);
    const char *invalid_lengths[] = {"null", "0", "-1", "1.5", "2147483648", "true", "\"8192\"", "[]", "{}"};
    for (size_t i = 0; i < ARRAY_SIZE(invalid_lengths); ++i)
    {
        testKernelQueueSettings("true", invalid_lengths[i], false, false, 0);
        testKernelQueueSettings("false", invalid_lengths[i], false, false, 0);
    }

    networkloggerDestroy();
    puts("TunDevice GSO/multiqueue/kernel queue configuration and checksum capability tests passed");
    return 0;
}
