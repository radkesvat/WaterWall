#include "TunDevice/interface.h"
#include "TunDevice/structure.h"

#include "loggers/network_logger.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "tundevice_gso_configuration_test: %s\n", message);
        exit(1);
    }
}

static void testGsoSetting(const char *json_value, bool valid, bool expected_request)
{
    cJSON *settings =
        cJSON_Parse("{\"device-name\":\"ww-fixture\",\"device-ip\":\"192.0.2.1/24\",\"device-mtu\":1500}");
    require(settings != NULL, "cannot parse TunDevice settings fixture");

    if (json_value != NULL)
    {
        cJSON *value = cJSON_Parse(json_value);
        require(value != NULL, "cannot parse GSO value fixture");
        require(cJSON_AddItemToObject(settings, "gso", value), "cannot add GSO value fixture");
    }

    node_t    node   = {.node_settings_json = settings};
    tunnel_t *tunnel = tundeviceTunnelCreate(&node);
    require((tunnel != NULL) == valid, "GSO setting accepted or rejected incorrectly");
    if (tunnel != NULL)
    {
        tundevice_tstate_t *state = tunnelGetState(tunnel);
        require(state->gso_requested == expected_request, "GSO setting had the wrong default or value");
        tundeviceTunnelDestroy(tunnel, wwLifecycleStartupRollback());
    }
    cJSON_Delete(settings);
}

int main(void)
{
    logger_t *logger = loggerCreate();
    require(logger != NULL, "logger allocation failed");
    setNetworkLogger(logger);

    node_t metadata = nodeTunDeviceGet();
    require(metadata.required_padding_left == kTunVirtioHeaderSize, "Linux TUN headroom does not fit virtio header");
    memoryFree(metadata.type);

    testGsoSetting(NULL, true, true);
    testGsoSetting("true", true, true);
    testGsoSetting("false", true, false);
    testGsoSetting("null", false, false);
    testGsoSetting("0", false, false);
    testGsoSetting("\"true\"", false, false);
    testGsoSetting("[]", false, false);
    testGsoSetting("{}", false, false);

    networkloggerDestroy();
    puts("TunDevice GSO configuration tests passed");
    return 0;
}
