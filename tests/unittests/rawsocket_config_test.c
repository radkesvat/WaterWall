#include "RawSocket/structure.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static tunnel_t *createRawSocket(const char *settings_text, cJSON **settings_out)
{
    cJSON *settings = cJSON_Parse(settings_text);
    require(settings != NULL, "failed to parse RawSocket test settings");

    node_t    node = {.node_settings_json = settings, .hash_next = 1};
    tunnel_t *t    = rawsocketCreate(&node);

    *settings_out = settings;
    return t;
}

static void destroyRawSocket(tunnel_t *t, cJSON *settings)
{
    if (t != NULL)
    {
        rawsocketDestroy(t, wwLifecycleStartupRollback());
    }
    cJSON_Delete(settings);
}

static void requireRange(const ipmask_t *range, const char *ip, uint8_t prefix, const char *message)
{
    ip4_addr_t parsed;
    require(ip4AddrAddressToNetwork(ip, &parsed) != 0, "failed to parse an expected IPv4 address");

    const uint32_t mask_host = prefix == 0 ? 0 : 0xFFFFFFFFU << (32U - prefix);
    require(range->ip.type == IPADDR_TYPE_V4 && range->mask.type == IPADDR_TYPE_V4 &&
                lwip_ntohl(range->ip.u_addr.ip4.addr) == (lwip_ntohl(parsed.addr) & mask_host) &&
                lwip_ntohl(range->mask.u_addr.ip4.addr) == mask_host,
            message);
}

static void testAliasesAcceptSingleAndArray(void)
{
    static const struct
    {
        const char *settings;
        uint32_t    expected_count;
    } cases[] = {
        {"{\"capture-filter-mode\":\"source-ip\",\"capture-ips\":\"192.0.2.10\"}", 1},
        {"{\"capture-filter-mode\":\"source-ip\",\"capture-ips\":[\"192.0.2.10\",\"198.51.100.0/24\"]}", 2},
        {"{\"capture-filter-mode\":\"source-ip\",\"capture-ip\":\"192.0.2.10\"}", 1},
        {"{\"capture-filter-mode\":\"source-ip\",\"capture-ip\":[\"192.0.2.10\",\"198.51.100.0/24\"]}", 2},
        {"{\"capture-filter-mode\":\"source-ip\",\"listen-ips\":[\"192.0.2.10\",\"198.51.100.0/24\"]}", 2},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        cJSON    *settings = NULL;
        tunnel_t *t        = createRawSocket(cases[i].settings, &settings);
        require(t != NULL, "RawSocket rejected a supported capture-ip/capture-ips shape");

        rawsocket_tstate_t *state = tunnelGetState(t);
        require(state->capture_range_count == cases[i].expected_count,
                "RawSocket loaded the wrong number of capture ranges");
        requireRange(&state->capture_ranges[0], "192.0.2.10", 32, "RawSocket loaded a single IPv4 range incorrectly");
        if (cases[i].expected_count == 2)
        {
            requireRange(
                &state->capture_ranges[1], "198.51.100.0", 24, "RawSocket loaded an IPv4 CIDR range incorrectly");
        }

        destroyRawSocket(t, settings);
    }
}

static void testMissingOrEmptyCaptureListEnablesWriteOnlyMode(void)
{
    static const char *cases[] = {
        "{\"raw-device-name\":\"writer-only\"}",
        "{\"capture-ips\":[]}",
        "{\"capture-ip\":[]}",
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        cJSON    *settings = NULL;
        tunnel_t *t        = createRawSocket(cases[i], &settings);
        require(t != NULL, "RawSocket rejected write-only mode without capture ranges");

        rawsocket_tstate_t *state = tunnelGetState(t);
        require(state->capture_ranges == NULL && state->capture_range_count == 0,
                "write-only RawSocket unexpectedly retained capture ranges");
        require(state->capture_device_name == NULL, "write-only RawSocket allocated capture-device configuration");
        require(state->raw_device_name != NULL, "write-only RawSocket did not configure its raw writer");

        destroyRawSocket(t, settings);
    }
}

static void testSkipSysctlSetting(void)
{
    cJSON    *settings = NULL;
    tunnel_t *t        = createRawSocket("{\"skip-sysctl\":true}", &settings);
    require(t != NULL, "RawSocket rejected skip-sysctl=true");
    require(((rawsocket_tstate_t *) tunnelGetState(t))->skip_sysctl, "RawSocket did not retain skip-sysctl=true");
    destroyRawSocket(t, settings);

    settings = NULL;
    t        = createRawSocket("{}", &settings);
    require(t != NULL, "RawSocket rejected its default write-only settings");
    require(! ((rawsocket_tstate_t *) tunnelGetState(t))->skip_sysctl,
            "RawSocket did not default skip-sysctl to false");
    destroyRawSocket(t, settings);

    settings = NULL;
    t        = createRawSocket("{\"skip-sysctl\":\"true\"}", &settings);
    require(t == NULL, "RawSocket accepted a non-boolean skip-sysctl value");
    destroyRawSocket(t, settings);
}

static void testInvalidCaptureElementIsRejected(void)
{
    cJSON    *settings = NULL;
    tunnel_t *t =
        createRawSocket("{\"capture-filter-mode\":\"source-ip\",\"capture-ip\":[\"192.0.2.10\",42]}", &settings);
    require(t == NULL, "RawSocket accepted a non-string capture range");
    destroyRawSocket(t, settings);
}

int main(void)
{
    testAliasesAcceptSingleAndArray();
    testMissingOrEmptyCaptureListEnablesWriteOnlyMode();
    testSkipSysctlSetting();
    testInvalidCaptureElementIsRejected();
    return 0;
}
