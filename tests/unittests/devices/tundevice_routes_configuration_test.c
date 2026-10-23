/* Covers enabled IPv4 capture settings and rejection of declared IPv6 capture
 * before exclusions or startup side effects. Device and route operations are
 * inert; constructors never open an interface or mutate host routes.
 * CTest: waterwall.tundevice_routes_configuration_unit */
#include "TunDevice/structure.h"
#include "loggers/network_logger.h"
#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static unsigned device_creates, route_adds, default_probes;

tun_device_t *__wrap_tundeviceCreate(const char *, bool, bool, uint16_t, void *, TunReadEventHandle,
                                     device_fragment_policy_t);
bool          __wrap_tundeviceAddRoute(tun_device_t *, const char *, const char *);
bool          __wrap_tundeviceDetectDefaultInterface(tun_default_route_t *);

tun_device_t *__wrap_tundeviceCreate(const char *name, bool gso, bool multi_queue, uint16_t mtu, void *userdata,
                                     TunReadEventHandle callback, device_fragment_policy_t policy)
{
    discard name;
    discard gso;
    discard multi_queue;
    discard mtu;
    discard userdata;
    discard callback;
    discard policy;
    ++device_creates;
    return NULL;
}

bool __wrap_tundeviceAddRoute(tun_device_t *device, const char *cidr, const char *table)
{
    discard device;
    discard cidr;
    discard table;
    ++route_adds;
    return false;
}

bool __wrap_tundeviceDetectDefaultInterface(tun_default_route_t *route)
{
    discard route;
    ++default_probes;
    return false;
}

static void settingsCase(const char *name, const char *extra, bool valid, const char *const *routes, size_t count)
{
    testCaseSet(name);
    char      json[2048];
    const int written = snprintf(json,
                                 sizeof(json),
                                 "{\"device-name\":\"ww-route-fixture\",\"device-ip\":\"192.0.2.1/24\","
                                 "\"device-mtu\":1500,%s}",
                                 extra);
    require(written > 0 && (size_t) written < sizeof(json), "route fixture JSON overflowed");
    cJSON *settings = cJSON_Parse(json);
    require(settings != NULL, "cannot parse route settings fixture");
    node_t node    = {.node_settings_json = settings};
    device_creates = route_adds = default_probes = 0;
    tunnel_t *tunnel                             = tundeviceTunnelCreate(&node);
    require((tunnel != NULL) == valid, "route settings accepted or rejected incorrectly");
    require(device_creates == 0 && route_adds == 0 && default_probes == 0,
            "route settings performed a startup side effect");
    if (tunnel != NULL)
    {
        tundevice_tstate_t *state = tunnelGetState(tunnel);
        require(state->system_route_count == count, "route subtraction/deduplication produced the wrong count");
        require(state->system_route_enabled == (count != 0), "route install enablement changed");
        for (size_t i = 0; i < count; ++i)
            require(strcmp(state->system_routes[i], routes[i]) == 0, "route CIDR/order changed");
        tundeviceTunnelDestroy(tunnel, wwLifecycleStartupRollback());
    }
    require(device_creates == 0 && route_adds == 0 && default_probes == 0,
            "constructor cleanup performed a startup side effect");
    cJSON_Delete(settings);
}

int main(void)
{
    logger_t *logger = loggerCreate();
    require(logger != NULL, "logger allocation failed");
    setNetworkLogger(logger);
    static const char *const defaults[]   = {"0.0.0.0/1", "128.0.0.0/1"};
    static const char *const subtracted[] = {"10.0.0.0/9", "192.168.0.0/16"};
    settingsCase("enabled routes default to split IPv4",
                 "\"system-route\":true,\"loop-protection\":false",
                 true,
                 defaults,
                 ARRAY_SIZE(defaults));
    settingsCase("IPv4 capture subtraction and deduplication",
                 "\"route-table\":\"main\",\"loop-protection\":false,"
                 "\"route-cidrs\":[\"10.0.0.0/8\",\"10.0.0.0/8\",\"192.168.0.0/16\"],"
                 "\"route-exclude-cidrs\":[\"10.128.0.0/9\"]",
                 true,
                 subtracted,
                 ARRAY_SIZE(subtracted));
    settingsCase(
        "IPv6-only capture is rejected", "\"system-route\":true,\"route-cidrs\":[\"2001:db8::/32\"]", false, NULL, 0);
    settingsCase(
        "IPv6 default capture is rejected", "\"system-route\":true,\"route-cidrs\":[\"::/0\"]", false, NULL, 0);
    settingsCase("mixed capture is rejected as a whole",
                 "\"system-route\":true,\"route-cidrs\":[\"10.0.0.0/8\",\"2001:db8::/32\"]",
                 false,
                 NULL,
                 0);
    settingsCase("excluded IPv6 declaration is still rejected",
                 "\"system-route\":true,\"route-cidrs\":[\"10.0.0.0/8\",\"2001:db8::/32\"],"
                 "\"route-exclude-cidrs\":[\"::/0\"]",
                 false,
                 NULL,
                 0);
    settingsCase("opposite-family exclusions are harmless",
                 "\"system-route\":true,\"loop-protection\":false,\"route-exclude-cidrs\":[\"::/0\"]",
                 true,
                 defaults,
                 ARRAY_SIZE(defaults));
    settingsCase("disabled routes ignore IPv6 capture declarations",
                 "\"system-route\":true,\"route-table\":\"off\",\"route-cidrs\":[\"::/0\"]",
                 true,
                 NULL,
                 0);
    settingsCase("invalid IPv4 capture stays rejected",
                 "\"system-route\":true,\"route-cidrs\":[\"192.0.2.1/33\"]",
                 false,
                 NULL,
                 0);
    networkloggerDestroy();
    puts("TunDevice capture route constructor settings passed");
    return 0;
}
