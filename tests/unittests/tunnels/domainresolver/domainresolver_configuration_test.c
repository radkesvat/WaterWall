/*
 * Covers native-only DomainResolver construction without registered connectors,
 * optional chain DNS egress, strict numeric endpoint grammar, and rejected mode-specific settings.
 * No sockets, worker loop, or external resolver are used.
 * CTest: waterwall.domainresolver_configuration_unit
 */
#include "DomainResolver/structure.h"
#include "loggers/network_logger.h"
#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static tunnel_t *createResolver(cJSON *settings)
{
    static node_t node;
    node = (node_t) {.name               = (char *) "resolve",
                     .type               = (char *) "DomainResolver",
                     .next               = (char *) "app-out",
                     .node_settings_json = settings};
    return domainresolverTunnelCreate(&node);
}

static void requireSettingsRejected(const char *json)
{
    cJSON *settings = cJSON_Parse(json);
    require(settings != NULL, "invalid test settings JSON");
    require(createResolver(settings) == NULL, "invalid mode or endpoint accepted");
    cJSON_Delete(settings);
}

int main(void)
{
    testCaseSet("domainresolver_configuration_test");
    require(createNetworkLogger(NULL, false) != NULL, "network logger setup failed");
    GSTATE.workers_count = 1;
    asyncdnsOptionsSetDefaults(&GSTATE.dns_options);
    // No registered TcpUdpConnector, and no dynamic-library discovery.
    configPolicyRestrict();

    for (unsigned explicit_mode = 0; explicit_mode < 2; ++explicit_mode)
    {
        cJSON    *settings = explicit_mode ? cJSON_Parse("{\"mode\":\"native\"}") : NULL;
        tunnel_t *resolver = createResolver(settings);
        require(resolver != NULL, "native resolver requires unavailable connector");
        domainresolver_tstate_t *ts = tunnelGetState(resolver);
        require(ts->mode == kDomainResolverModeNative && ts->dns_connector == NULL && ts->dns_workers == NULL,
                "native construction created line transport state");
        domainresolverTunnelDestroy(resolver, wwLifecycleStartupRollback());
        cJSON_Delete(settings);
    }
    requireSettingsRejected("{\"mode\":\"direct\",\"servers\":[\"127.0.0.1:53\"]}");
    // An unavailable direct connector must not poison later native creation.
    tunnel_t *native = createResolver(NULL);
    require(native != NULL, "failed direct construction damaged native support");
    domainresolverTunnelDestroy(native, wwLifecycleStartupRollback());

    const char *invalid_settings[] = {
        "{\"mode\":\"chain\",\"servers\":[\"127.0.0.1\"],\"dns-next\":null}",
        "{\"mode\":\"chain\",\"servers\":[\"127.0.0.1\"],\"dns-next\":\"\"}",
        "{\"mode\":\"chain\",\"servers\":[\"127.0.0.1\"],\"dns-next\":false}",
        "{\"mode\":\"chain\",\"servers\":[\"127.0.0.1\"],\"dns-next\":1}",
        "{\"mode\":\"chain\",\"servers\":[\"127.0.0.1\"],\"dns-next\":[]}",
        "{\"mode\":\"chain\",\"servers\":[\"127.0.0.1\"],\"dns-next\":{}}",
        "{\"mode\":\"chain\",\"servers\":[\"127.0.0.1\"],\"dns-next\":\"resolve\"}",
        "{\"mode\":\"chain\"}",
        "{\"dns-next\":\"app-out\"}",
        "{\"mode\":\"native\",\"dns-next\":null}",
        "{\"mode\":\"native\",\"servers\":[\"127.0.0.1\"]}",
        "{\"mode\":\"direct\",\"servers\":[\"127.0.0.1\"],\"dns-next\":\"app-out\"}",
        "{\"mode\":\"direct\",\"servers\":[\"127.0.0.1\"],\"dns-next\":null}",
    };
    for (size_t i = 0; i < sizeof(invalid_settings) / sizeof(invalid_settings[0]); ++i)
    {
        testCaseSet(invalid_settings[i]);
        requireSettingsRejected(invalid_settings[i]);
    }

    const char *invalid_endpoints[] = {"127.1",
                                       "2130706433",
                                       "0177.0.0.1",
                                       "0x7f.0.0.1",
                                       "127.0.0.1 ",
                                       "localhost",
                                       "127.0.0.1:0",
                                       "127.0.0.1:65536",
                                       "[::1]:",
                                       "[::1]:-1",
                                       "[127.0.0.1]:53",
                                       "[fe80::1%lo]:53"};
    for (size_t i = 0; i < sizeof(invalid_endpoints) / sizeof(invalid_endpoints[0]); ++i)
    {
        testCaseSet(invalid_endpoints[i]);
        cJSON *settings = cJSON_CreateObject();
        cJSON_AddStringToObject(settings, "mode", "chain");
        cJSON_AddStringToObject(settings, "dns-next", "dns-out");
        cJSON *servers = cJSON_AddArrayToObject(settings, "servers");
        cJSON_AddItemToArray(servers, cJSON_CreateString(invalid_endpoints[i]));
        require(createResolver(settings) == NULL, "noncanonical or malformed server endpoint accepted");
        cJSON_Delete(settings);
    }
    const char *dns_entries[] = {NULL, "app-out", "dns-out"};
    for (size_t i = 0; i < sizeof(dns_entries) / sizeof(dns_entries[0]); ++i)
    {
        testCaseSet(dns_entries[i] == NULL ? "omitted chain dns-next" : dns_entries[i]);
        cJSON *settings = cJSON_Parse("{\"mode\":\"chain\","
                                      "\"servers\":[\"127.0.0.1:5353\",\"2001:db8::53\",\"[::1]:5353\"]}");
        require(settings != NULL, "valid test settings JSON failed");
        if (dns_entries[i] != NULL)
            cJSON_AddStringToObject(settings, "dns-next", dns_entries[i]);
        tunnel_t *chain = createResolver(settings);
        require(chain != NULL, "valid chain DNS egress or numeric IPv4/IPv6 endpoints rejected");
        domainresolver_tstate_t *ts = tunnelGetState(chain);
        require(ts->mode == kDomainResolverModeChain &&
                    (dns_entries[i] == NULL ? ts->dns_next == NULL
                                            : ts->dns_next != NULL && strcmp(ts->dns_next, dns_entries[i]) == 0),
                "omitted, same-next, or override DNS egress was not preserved");
        require(strcmp(chain->node->next, "app-out") == 0, "DNS configuration changed the application next");
        require(strcmp(ts->dns_options.servers_csv, "127.0.0.1:5353,2001:db8::53,[::1]:5353") == 0,
                "server endpoint ports or order changed");
        domainresolverTunnelDestroy(chain, wwLifecycleStartupRollback());
        cJSON_Delete(settings);
    }
    nodelibraryCleanup();
    networkloggerDestroy();
    return 0;
}
