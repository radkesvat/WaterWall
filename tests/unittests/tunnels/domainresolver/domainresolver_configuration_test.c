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

static void testSharedPolicy(void)
{
    const dns_policy_defaults_t defaults = {
        .resolve       = false,
        .strategy      = kDsInvalid,
        .core_strategy = kDsPreferIpV6,
    };
    static const struct
    {
        const char          *json;
        bool                 valid;
        bool                 resolve;
        enum domain_strategy strategy;
    } cases[] = {
        {"{}", true, false, kDsInvalid},
        {"{\"dns-behaviour\":{\"resolve\":false}}", true, false, kDsInvalid},
        {"{\"dns-behaviour\":{\"resolve\":true}}", true, true, kDsInvalid},
        {"{\"dns-behaviour\":{\"resolve\":true,\"strategy\":\"core-settings\"}}", true, true, kDsPreferIpV6},
        {"{\"dns-behaviour\":{\"resolve\":true,\"strategy\":\"only-ipv4\"}}", true, true, kDsOnlyIpV4},
        {"{\"dns-behaviour\":null}", false, false, kDsInvalid},
        {"{\"dns-behaviour\":[]}", false, false, kDsInvalid},
        {"{\"dns-behaviour\":{}}", false, false, kDsInvalid},
        {"{\"dns-behaviour\":{\"strategy\":\"only-ipv4\"}}", false, false, kDsInvalid},
        {"{\"dns-behaviour\":{\"resolve\":1}}", false, false, kDsInvalid},
        {"{\"dns-behaviour\":{\"resolve\":null}}", false, false, kDsInvalid},
        {"{\"dns-behaviour\":{\"resolve\":true,\"extra\":true}}", false, false, kDsInvalid},
        {"{\"dns-behaviour\":{\"resolve\":true,\"strategy\":1}}", false, false, kDsInvalid},
        {"{\"dns-behaviour\":{\"resolve\":true,\"strategy\":\"ONLY-IPV4\"}}", false, false, kDsInvalid},
        {"{\"dns-behaviour\":{\"resolve\":true,\"mode\":\"NATIVE\"}}", false, false, kDsInvalid},
        {"{\"dns-behaviour\":{\"resolve\":false,\"strategy\":\"only-ipv4\"}}", false, false, kDsInvalid},
        {"{\"dns-behaviour\":{\"resolve\":false,\"mode\":\"native\"}}", false, false, kDsInvalid},
        {"{\"dns-behaviour\":{\"resolve\":false,\"servers\":[]}}", false, false, kDsInvalid},
        {"{\"dns-behaviour\":{\"resolve\":false,\"dns-next\":null}}", false, false, kDsInvalid},
        {"{\"domain-strategy\":null,\"dns-behaviour\":{\"resolve\":true}}", false, false, kDsInvalid},
        {"{\"resolve-domains\":false,\"dns-behaviour\":{\"resolve\":false}}", false, false, kDsInvalid},
        {"{\"dns-behaviour\":{\"resolve\":true,\"mode\":\"native\\u0000suffix\"}}", false, false, kDsInvalid},
        {"{\"dns-behaviour\":{\"resolve\":true,\"strategy\":\"only-ipv4\\u0000suffix\"}}", false, false, kDsInvalid},
        {"{\"dns-behaviour\":{\"resolve\\u0000suffix\":true}}", false, false, kDsInvalid},
        {"{\"dns-behaviour\\u0000suffix\":{\"resolve\":true}}", false, false, kDsInvalid},
        {"{\"dns-behaviour\":{\"resolve\":true,\"resolve\":false}}", false, false, kDsInvalid},
        {"{\"dns-behaviour\":{\"resolve\":true,\"mode\":\"chain\",\"servers\":[\"127.0.0.1\\u0000suffix\"]}}",
         false,
         false,
         kDsInvalid},
        {"{\"dns-behaviour\":{\"resolve\":true,\"mode\":\"chain\",\"servers\":[\"127.0.0.1\"],\"dns-next\":"
         "\"entry\\u0000suffix\"}}",
         false,
         false,
         kDsInvalid},

    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        testCaseSet(cases[i].json);
        cJSON       *settings = cJSON_Parse(cases[i].json);
        dns_policy_t policy;
        require(dnsPolicyParseSettings(&policy, settings, &defaults, "test.dns-behaviour") == cases[i].valid,
                "common policy validity differs");
        if (cases[i].valid)
            require(policy.resolve == cases[i].resolve && policy.strategy == cases[i].strategy,
                    "common policy lost defaults or effective values");
        dnsPolicyDestroy(&policy);
        cJSON_Delete(settings);
    }
    const char *strategies[] = {"accept-dns-returned-order", "prefer-ipv4", "prefer-ipv6", "only-ipv4", "only-ipv6"};
    for (size_t i = 0; i < sizeof(strategies) / sizeof(strategies[0]); ++i)
    {
        cJSON               *value = cJSON_CreateString(strategies[i]);
        enum domain_strategy strategy;
        require(dnsPolicyParseStrategy(value, defaults.core_strategy, &strategy), "canonical strategy rejected");
        require(strcmp(dnsPolicyStrategyName(strategy), strategies[i]) == 0, "strategy round trip changed");
        cJSON_Delete(value);
    }
    const char *invalid_overrides[] = {
        "{\"dns-behaviour\":{\"strategy\":\"only-ipv4\\u0000suffix\"}}",
        "{\"dns-behaviour\":{\"strategy\\u0000suffix\":\"only-ipv4\"}}",
        "{\"dns-behaviour\":{\"strategy\":\"only-ipv4\",\"strategy\":\"only-ipv6\"}}",
        "{\"dns-behaviour\":{\"resolve\":true}}",
    };
    for (size_t i = 0; i < sizeof(invalid_overrides) / sizeof(invalid_overrides[0]); ++i)
    {
        cJSON               *override = cJSON_Parse(invalid_overrides[i]);
        enum domain_strategy strategy = kDsOnlyIpV4;
        require(! dnsPolicyParseStrategyOverride(&strategy, override, true, "weighted"),
                "invalid weighted strategy override accepted");
        cJSON_Delete(override);
    }
    cJSON                *settings   = cJSON_Parse("{\"dns-behaviour\":{\"resolve\":true,\"mode\":\"chain\","
                                                   "\"servers\":[\"127.0.0.1:53\"]}}");
    dns_policy_defaults_t restricted = defaults;
    restricted.require_dns_next      = true;
    dns_policy_t policy;
    require(! dnsPolicyParseSettings(&policy, settings, &restricted, "restricted"), "required DNS branch omitted");
    dnsPolicyDestroy(&policy);
    cJSON_AddStringToObject(cJSON_GetObjectItemCaseSensitive(settings, "dns-behaviour"), "dns-next", "dns-out");
    require(dnsPolicyParseSettings(&policy, settings, &restricted, "restricted"), "explicit DNS branch rejected");
    cJSON       *flat = dnsPolicyCreateResolverSettings(&policy);
    dns_policy_t copy;
    require(dnsPolicyParseFlat(&copy, flat, &defaults, "flat"), "effective helper policy rejected");
    require(copy.mode == policy.mode && strcmp(copy.servers_csv, policy.servers_csv) == 0 &&
                strcmp(copy.dns_next, policy.dns_next) == 0,
            "helper policy lost explicit transport");
    dnsPolicyDestroy(&copy);
    dnsPolicyDestroy(&policy);
    cJSON_Delete(flat);
    restricted.ipv4_only = true;
    require(! dnsPolicyParseSettings(&policy, settings, &restricted, "ipv4-only"), "IPv4-only restriction ignored");
    dnsPolicyDestroy(&policy);
    cJSON_Delete(settings);
}

int main(void)
{
    testCaseSet("domainresolver_configuration_test");
    require(createNetworkLogger(NULL, false) != NULL, "network logger setup failed");
    testSharedPolicy();
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
    cJSON    *disabled_settings = cJSON_Parse("{\"resolve\":false}");
    tunnel_t *disabled          = createResolver(disabled_settings);
    require(disabled != NULL && ! domainresolverTunnelResolutionEnabled(disabled), "flat disabled resolver rejected");
    domainresolverTunnelDestroy(disabled, wwLifecycleStartupRollback());
    cJSON_Delete(disabled_settings);
    requireSettingsRejected("{\"resolve\":false,\"strategy\":\"only-ipv4\"}");
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
