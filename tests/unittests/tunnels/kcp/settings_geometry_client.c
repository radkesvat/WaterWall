/*
 * Configuration and packet geometry regressions for KcpClient.
 * Runs within the paired fixture's initialized worker runtime. Both builds
 * exercise strict close integer parsing, defaults, and every MTU boundary.
 * CTest: waterwall.kcp_session_unit (Debug and Release).
 */
#include "KcpClient/interface.h"
#include "KcpClient/structure.h"
#include "settings_geometry_cases.h"

static void settingsRequire(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "KcpClient settings/geometry: %s\n", message);
        abort();
    }
}

static tunnel_t *settingsCreate(node_t *node, const char *json)
{
    *node                    = nodeKcpClientGet();
    node->node_settings_json = cJSON_Parse(json);
    settingsRequire(node->node_settings_json != NULL, "fixture JSON failed to parse");
    return node->createHandle(node);
}

static void settingsDestroy(node_t *node, tunnel_t *tunnel)
{
    if (tunnel != NULL)
        tunnel->onDestroy(tunnel, wwLifecycleStartupRollback());
    cJSON_Delete(node->node_settings_json);
    memoryFree(node->type);
}

void kcpClientSettingsGeometryCases(void)
{
    static const char *invalid[] = {
        "{\"close-drain-timeout-ms\":0}",
        "{\"close-drain-timeout-ms\":-1}",
        "{\"close-drain-timeout-ms\":1.5}",
        "{\"close-drain-timeout-ms\":1e1}",
        "{\"close-drain-timeout-ms\":1.0}",
        "{\"close-drain-timeout-ms\":2147483648}",
        "{\"close-drain-timeout-ms\":9223372036854775808}",
        "{\"close-drain-timeout-ms\":null}",
        "{\"close-drain-timeout-ms\":true}",
        "{\"close-drain-timeout-ms\":\"30000\"}",
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        node_t    node;
        tunnel_t *tunnel = settingsCreate(&node, invalid[i]);
        settingsRequire(tunnel == NULL, "invalid close interval accepted");
        settingsDestroy(&node, tunnel);
    }
    static const char    *valid[] = {"{}", "{\"close-drain-timeout-ms\":1}", "{\"close-drain-timeout-ms\":2147483647}"};
    static const uint32_t expected[] = {30000U, 1U, INT_MAX};
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i)
    {
        node_t    node;
        tunnel_t *tunnel = settingsCreate(&node, valid[i]);
        settingsRequire(tunnel != NULL, "valid close interval rejected");
        kcpclient_tstate_t *state = tunnelGetState(tunnel);
        settingsRequire(state->close_drain_timeout_ms == expected[i], "close interval/default changed");
        settingsDestroy(&node, tunnel);
    }
    static const char *invalid_send_mtu[] = {
        "{\"send-mtu\":null}",
        "{\"send-mtu\":true}",
        "{\"send-mtu\":\"1500\"}",
        "{\"send-mtu\":1500.5}",
        "{\"send-mtu\":-1}",
    };
    for (size_t i = 0; i < ARRAY_SIZE(invalid_send_mtu); ++i)
    {
        node_t    node;
        tunnel_t *tunnel = settingsCreate(&node, invalid_send_mtu[i]);
        settingsRequire(tunnel == NULL, "invalid send-mtu accepted");
        settingsDestroy(&node, tunnel);
    }
    const uint16_t inherited_mtu = CORE_DEFAULT_MTU;
    node_t         inherited_node;
    tunnel_t      *inherited = settingsCreate(&inherited_node, "{}");
    settingsRequire(inherited != NULL, "inherited sending MTU rejected");
    settingsRequire(((kcpclient_tstate_t *) tunnelGetState(inherited))->send_mtu == inherited_mtu,
                    "send-mtu did not inherit core misc.mtu");
    node_t    explicit_node;
    tunnel_t *explicit_mtu = settingsCreate(&explicit_node, "{\"send-mtu\":1200}");
    settingsRequire(explicit_mtu != NULL, "explicit sending MTU rejected");
    settingsRequire(((kcpclient_tstate_t *) tunnelGetState(explicit_mtu))->send_mtu == 1200 &&
                        CORE_DEFAULT_MTU == inherited_mtu &&
                        ((kcpclient_tstate_t *) tunnelGetState(inherited))->send_mtu == inherited_mtu,
                    "send-mtu override changed another node or the core default");
    settingsDestroy(&explicit_node, explicit_mtu);
    settingsDestroy(&inherited_node, inherited);
    for (unsigned fec = 0; fec < 2; ++fec)
    {
        const unsigned minimum = fec ? 126U : 118U;
        const unsigned cap_at  = fec ? 64076U : 64068U;
        const unsigned mtus[]  = {minimum - 1, minimum, minimum + 1, 1500, cap_at - 1, cap_at, 65535, 65536};
        for (size_t i = 0; i < sizeof(mtus) / sizeof(mtus[0]); ++i)
        {
            char json[128];
            snprintf(json, sizeof(json), "{\"send-mtu\":%u,\"fec\":%s}", mtus[i], fec ? "true" : "false");
            node_t    node;
            tunnel_t *tunnel = settingsCreate(&node, json);
            if (mtus[i] < minimum || mtus[i] > UINT16_MAX)
                settingsRequire(tunnel == NULL, "out-of-range MTU accepted");
            else
            {
                settingsRequire(tunnel != NULL, "valid boundary MTU rejected");
                kcpclient_tstate_t *state        = tunnelGetState(tunnel);
                const int           expected_mtu = min((int) mtus[i] - 68 - (fec ? 8 : 0), 64000);
                const int           kcp_mtu      = kcpclientGetKcpMtu(state);
                settingsRequire(kcp_mtu == expected_mtu, "outer session/FEC envelope was not deducted");
                settingsRequire(kcpclientGetKcpWriteMtu(state) == expected_mtu - 25,
                                "application chunk geometry changed");
                settingsRequire(kcp_mtu + 68 + (fec ? 8 : 0) <= (int) mtus[i], "wire packet exceeded MTU");
            }
            settingsDestroy(&node, tunnel);
        }
    }
}
