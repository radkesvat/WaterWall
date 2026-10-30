/* Covers enabled IPv4 capture settings and rejection of declared IPv6 capture
 * before exclusions or startup side effects. Device and route operations are
 * inert; constructors never open an interface or mutate host routes.
 * CTest: waterwall.tundevice_routes_configuration_unit */
#include "TunDevice/structure.h"
#include "loggers/network_logger.h"
#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static unsigned                  device_creates, route_adds, default_probes;
static device_opaque_flow_mode_t constructed_mode;

tun_device_t *__wrap_tundeviceCreate(const char *, bool, bool, uint16_t, void *, TunReadEventHandle,
                                     device_fragment_policy_t, device_opaque_flow_mode_t);
bool          __wrap_tundeviceAddRoute(tun_device_t *, const char *, const char *);
bool          __wrap_tundeviceDetectDefaultInterface(tun_default_route_t *);

tun_device_t *__wrap_tundeviceCreate(const char *name, bool gso, bool multi_queue, uint16_t mtu, void *userdata,
                                     TunReadEventHandle callback, device_fragment_policy_t policy,
                                     device_opaque_flow_mode_t opaque_flow_mode)
{
    discard name;
    discard gso;
    discard multi_queue;
    discard mtu;
    discard userdata;
    discard callback;
    discard policy;
    constructed_mode = opaque_flow_mode;
    require(opaque_flow_mode != kDeviceOpaqueFlowAuto, "TUN constructor received unresolved auto");
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

static void startupModeCase(const char *value, bool upstream, const char *peer_type, device_opaque_flow_mode_t expected)
{
    testCaseSet("opaque mode resolves before native TUN construction");
    cJSON *settings = cJSON_Parse("{\"device-name\":\"ww-mode-fixture\",\"device-ip\":\"192.0.2.1/24\","
                                  "\"device-mtu\":1500,\"loop-protection\":false}");
    require(settings != NULL, "cannot create startup mode fixture");
    if (value != NULL)
        require(cJSON_AddStringToObject(settings, "opaque-flow-mode", value) != NULL,
                "cannot configure startup mode fixture");
    node_t    node      = {.node_settings_json = settings, .hash_next = upstream ? 1 : 0};
    node_t    peer_node = {.type = (char *) peer_type};
    tunnel_t *device    = tundeviceTunnelCreate(&node);
    tunnel_t *peer      = packettunnelCreate(&peer_node, 0, 0);
    require(device != NULL && peer != NULL, "cannot create startup mode topology");
    if (upstream)
        tunnelBind(device, peer);
    else
        tunnelBind(peer, device);
    device_creates               = 0;
    constructed_mode             = kDeviceOpaqueFlowAuto;
    ww_startup_context_t context = {0};
    wwStartupContextBegin(&context);
    tundeviceTunnelOnStart(device);
    require(! wwStartupSucceeded(wwStartupContextEnd(&context)), "inert failed constructor did not stop startup");
    const tundevice_tstate_t *state = tunnelGetState(device);
    require(device_creates == 1 && constructed_mode == expected && state->opaque_flow_mode_effective == expected,
            "startup did not pass resolved opaque mode to TUN constructor");
    require(state->opaque_flow_mode_requested ==
                (value != NULL && strcmp(value, "auto") == 0 ? kDeviceOpaqueFlowAuto : expected),
            "startup overwrote requested opaque mode");
    tundeviceTunnelDestroy(device, wwLifecycleStartupRollback());
    tunnelDestroy(peer);
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
    startupModeCase("auto", true, "PingServer", kDeviceOpaqueFlowPeer);
    startupModeCase("auto", false, "PingClient", kDeviceOpaqueFlowPeer);
    startupModeCase("auto", true, "PingClient", kDeviceOpaqueFlowPrefix);
    startupModeCase("auto", false, "PingServer", kDeviceOpaqueFlowPrefix);
    startupModeCase(NULL, true, "PingServer", kDeviceOpaqueFlowPrefix);
    startupModeCase("spread", true, "PingServer", kDeviceOpaqueFlowSpread);
    networkloggerDestroy();
    puts("TunDevice capture route constructor settings passed");
    return 0;
}
