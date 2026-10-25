/* Real VmessClient construction validates aliases, exact JSON types and every
 * exposed framing combination. No connection or external service is started.
 * CTest: waterwall.vmess_client_config_unit, Debug and Release. */
#include "VmessClient/internal.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "loggers/network_logger.h"

static const char *uuid = "5783a3e7-e373-51cd-8642-c83782b807c5";

static void construct(cJSON *settings, bool expected)
{
    node_t node             = nodeVmessClientGet();
    node.node_settings_json = settings;
    tunnel_t *t             = vmessclientTunnelCreate(&node);
    twfRequire((t != NULL) == expected, "configuration acceptance differs from the declared client contract");
    if (t != NULL)
        t->onDestroy(t, wwLifecycleStartupRollback());
    cJSON_Delete(settings);
    memoryFree(node.type);
}

static cJSON *settings(void)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "uuid", uuid);
    cJSON_AddStringToObject(json, "address", "127.0.0.1");
    cJSON_AddNumberToObject(json, "port", 443);
    return json;
}

static void aliases(void)
{
    const char *credentials[] = {"uuid", "id", "user-id"};
    const char *addresses[]   = {"address", "target-address", "target"};
    const char *protocols[]   = {"protocol", "proto"};
    const char *values[]      = {
        "tcp", "connect", "udp", "udp-associate", "dest_context->protocol", "line->dest_ctx->protocol"};
    for (size_t c = 0; c < ARRAY_SIZE(credentials); ++c)
        for (size_t a = 0; a < ARRAY_SIZE(addresses); ++a)
            for (size_t p = 0; p < ARRAY_SIZE(protocols); ++p)
                for (size_t v = 0; v < ARRAY_SIZE(values); ++v)
                {
                    cJSON *json = cJSON_CreateObject();
                    cJSON_AddStringToObject(json, credentials[c], c == 1 ? "5783A3E7E37351CD8642C83782B807C5" : uuid);
                    cJSON_AddStringToObject(json, addresses[a], a == 1 ? "line->dest_ctx->address" : "example.test");
                    if (a == 1)
                        cJSON_AddStringToObject(json, "port", "line->dest_ctx->port");
                    else
                        cJSON_AddNumberToObject(json, "port", 65535);
                    cJSON_AddStringToObject(json, protocols[p], values[v]);
                    construct(json, true);
                }
    const char *duplicates[] = {
        "uuid", "id", "user-id", "address", "target-address", "target", "port", "protocol", "proto"};
    for (size_t i = 0; i < ARRAY_SIZE(duplicates); ++i)
    {
        cJSON *json = settings();
        cJSON_AddStringToObject(json, "protocol", "tcp");
        cJSON_AddStringToObject(json, duplicates[i], "tcp");
        construct(json, false);
    }
}

static void modes(void)
{
    const char *names[] = {"aes-128-gcm", "chacha20-poly1305", "none", "zero"};
    for (size_t s = 0; s < ARRAY_SIZE(names); ++s)
        for (unsigned udp = 0; udp < 2; ++udp)
            for (unsigned flags = 0; flags < 8; ++flags)
            {
                cJSON *json = settings();
                cJSON_AddStringToObject(json, "security", names[s]);
                cJSON_AddStringToObject(json, "protocol", udp ? "udp" : "tcp");
                cJSON_AddBoolToObject(json, "chunk-masking", (flags & 1) != 0);
                cJSON_AddBoolToObject(json, "global-padding", (flags & 2) != 0);
                cJSON_AddBoolToObject(json, "authenticated-length", (flags & 4) != 0);
                const uint8_t options  = s == 3 ? 0
                                                : VMESS_OPTION_CHUNK | ((flags & 1) ? VMESS_OPTION_MASK : 0) |
                                                     ((flags & 2) ? VMESS_OPTION_PADDING : 0) |
                                                     ((flags & 4) ? VMESS_OPTION_AUTH_LENGTH : 0);
                bool          expected = s < 2 ? options == 1 || options == 5 || options == 13 || options == 17 ||
                                            options == 21 || options == 29
                                         : s == 2 ? options == 1 || options == 5 || (udp && options == 13)
                                                  : flags == 0 && ! udp;
                construct(json, expected);
            }
    construct(settings(), true);
}

static void strategies(void)
{
    const char *names[] = {"do-not-resolve-domains",
                           "resolve-domains-and-accept-dns-returned-order",
                           "resolve-domains-and-prefer-ipv4",
                           "resolve-domains-and-prefer-ipv6",
                           "resolve-domains-and-use-only-ipv4",
                           "resolve-domains-and-use-only-ipv6",
                           "resolve-domains-with-core-settings"};
    for (size_t i = 0; i < ARRAY_SIZE(names); ++i)
    {
        cJSON *json = settings();
        cJSON_AddStringToObject(json, "domain-strategy", names[i]);
        construct(json, true);
    }
    cJSON *json = settings();
    cJSON_AddStringToObject(json, "domain-strategy", "unknown");
    construct(json, false);
}

static void invalidTypes(void)
{
    const char *fields[] = {"uuid",
                            "address",
                            "port",
                            "protocol",
                            "domain-strategy",
                            "security",
                            "first-payload-timeout-ms",
                            "chunk-masking",
                            "global-padding",
                            "authenticated-length",
                            "verbose"};
    const char *types[]  = {"null", "[]", "{}", "true", "1", "\"\""};
    for (size_t i = 0; i < ARRAY_SIZE(fields); ++i)
        for (size_t j = 0; j < ARRAY_SIZE(types); ++j)
        {
            /* Exact booleans and an integral port/timeout are valid values. */
            if ((i >= 7 && j == 3) || ((i == 2 || i == 6) && j == 4))
                continue;
            cJSON *json = settings();
            cJSON_DeleteItemFromObjectCaseSensitive(json, fields[i]);
            cJSON_AddItemToObject(json, fields[i], cJSON_Parse(types[j]));
            construct(json, false);
        }
    const char *bad[] = {"-1", "0.5", "4294967296", "1e100", "\"400\""};
    for (size_t i = 0; i < ARRAY_SIZE(bad); ++i)
    {
        cJSON *json = settings();
        cJSON_AddItemToObject(json, "first-payload-timeout-ms", cJSON_Parse(bad[i]));
        construct(json, false);
    }
    const char *unsupported[] = {
        "alterId", "alter-id", "users", "authentication-client", "user-controller", "fallback"};
    for (size_t i = 0; i < ARRAY_SIZE(unsupported); ++i)
    {
        cJSON *json = settings();
        cJSON_AddNullToObject(json, unsupported[i]);
        construct(json, false);
    }
    const char *invalidPorts[] = {"0", "65536", "1.5", "-1", "\"443\""};
    for (size_t i = 0; i < ARRAY_SIZE(invalidPorts); ++i)
    {
        cJSON *json = settings();
        cJSON_ReplaceItemInObjectCaseSensitive(json, "port", cJSON_Parse(invalidPorts[i]));
        construct(json, false);
    }
    for (unsigned i = 0; i < 2; ++i)
    {
        cJSON *json = settings();
        cJSON_AddNumberToObject(json, "first-payload-timeout-ms", i ? UINT32_MAX : 0);
        construct(json, true);
    }
    char domain[257];
    memorySet(domain, 'a', sizeof(domain));
    domain[255] = '\0';
    cJSON *json = settings();
    cJSON_ReplaceItemInObjectCaseSensitive(json, "address", cJSON_CreateString(domain));
    construct(json, true);
    domain[255] = 'a';
    domain[256] = '\0';
    json        = settings();
    cJSON_ReplaceItemInObjectCaseSensitive(json, "address", cJSON_CreateString(domain));
    construct(json, false);
}

static void exactStrings(void)
{
    /* Parse whole objects: C-string setters would discard embedded-NUL evidence. */
    const char *invalid[] = {
        "{\"uuid\":\"5783a3e7-e373-51cd-8642-c83782b807c5\\u0000suffix\"}",
        "{\"id\":\"5783A3E7E37351CD8642C83782B807C5\\u0000suffix\"}",
        "{\"address\":\"127.0.0.1\\u0000other\"}",
        "{\"target-address\":\"example.test\\u0000other\"}",
        "{\"security\":\"none\\u0000suffix\"}",
        "{\"proto\":\"udp\\u0000suffix\"}",
        "{\"port\":\"dest_context->port\\u0000suffix\"}",
        "{\"domain-strategy\":\"do-not-resolve-domains\\u0000suffix\"}",
        "{\"uuid\\u0000other\":\"5783a3e7-e373-51cd-8642-c83782b807c5\"}",
        "{\"security\\u0000other\":\"none\"}",
        "{\"port\\u0000other\":443}",
        "{\"verbose\\u0000other\":true}",
        "{\"address\":\"example.\xff\"}",
        "{\"address\xff\":\"example.test\"}",
    };
    for (size_t i = 0; i < ARRAY_SIZE(invalid); ++i)
    {
        cJSON *json = cJSON_Parse(invalid[i]);
        twfRequire(json != NULL, "malformed setting must reach constructor validation");
        if (getJsonObjectItemByKeys(json, "uuid", "id", "user-id") == NULL)
            cJSON_AddStringToObject(json, "uuid", uuid);
        if (getJsonObjectItemByKeys(json, "target-address", "address", "target") == NULL)
            cJSON_AddStringToObject(json, "address", "127.0.0.1");
        if (cJSON_GetObjectItemCaseSensitive(json, "port") == NULL)
            cJSON_AddNumberToObject(json, "port", 443);
        construct(json, false);
    }

    cJSON *json = settings();
    cJSON_ReplaceItemInObjectCaseSensitive(json,
                                           "address",
                                           cJSON_CreateString("b\xc3\xbc"
                                                              "cher.example"));
    construct(json, true);
}

static void maturityOptions(void)
{
    cJSON *json             = settings();
    node_t node             = nodeVmessClientGet();
    node.node_settings_json = json;
    tunnel_t *t             = vmessclientTunnelCreate(&node);
    twfRequire(t != NULL, "default config rejected");
    vmessclient_tstate_t *ts = tunnelGetState(t);
    twfRequire(ts->counter_policy == kVmessCounterWrap && ts->send_termination && ! ts->packetaddr &&
                   ! ts->security_auto && ts->security == VMESS_SECURITY_AES128_GCM,
               "maturity feature defaults changed");
    twfRequire(nodeApiFind(t, "stats") != NULL, "stats operation is not registered");
    t->onDestroy(t, wwLifecycleStartupRollback());
    twfRequire(! nodeApiHasRegistration(t), "destroy leaked stats registration");
    cJSON_Delete(json);
    memoryFree(node.type);
    const char *policies[] = {"wrap", "strict"};
    for (size_t i = 0; i < ARRAY_SIZE(policies); ++i)
    {
        json = settings();
        cJSON_AddStringToObject(json, "encrypted-counter-policy", policies[i]);
        cJSON_AddBoolToObject(json, "send-termination", false);
        cJSON_AddStringToObject(json, "security", "auto");
        construct(json, true);
    }
    const char *fields[] = {"encrypted-counter-policy", "packet-encoding", "send-termination"};
    const char *bad[]    = {"null", "true", "1", "[]", "{}", "\"unknown\""};
    for (size_t i = 0; i < ARRAY_SIZE(fields); ++i)
        for (size_t j = 0; j < ARRAY_SIZE(bad); ++j)
        {
            if (i == 2 && j == 1)
                continue;
            json = settings();
            cJSON_AddItemToObject(json, fields[i], cJSON_Parse(bad[j]));
            construct(json, false);
        }
    for (size_t i = 0; i < ARRAY_SIZE(fields); ++i)
    {
        json = settings();
        cJSON_AddStringToObject(json, fields[i], "none");
        cJSON_AddStringToObject(json, fields[i], "none");
        construct(json, false);
    }
    for (unsigned dynamic = 0; dynamic < 2; ++dynamic)
    {
        json = settings();
        cJSON_AddStringToObject(json, "protocol", dynamic ? "dest_context->protocol" : "udp");
        cJSON_AddStringToObject(json, "packet-encoding", "packetaddr");
        construct(json, true);
    }
    json = settings();
    cJSON_AddStringToObject(json, "packet-encoding", "packetaddr");
    construct(json, false);
    json = settings();
    cJSON_ReplaceItemInObjectCaseSensitive(json, "uuid", cJSON_CreateString("waterwall"));
    construct(json, true);
    json = settings();
    cJSON_ReplaceItemInObjectCaseSensitive(json, "uuid", cJSON_CreateString("1234567890123456789012345678901"));
    construct(json, false);
    const char *nul[] = {"{\"encrypted-counter-policy\":\"wrap\\u0000strict\"}",
                         "{\"packet-encoding\":\"none\\u0000packetaddr\"}",
                         "{\"send-termination\\u0000other\":true}"};
    for (size_t i = 0; i < ARRAY_SIZE(nul); ++i)
    {
        json = cJSON_Parse(nul[i]);
        cJSON_AddStringToObject(json, "uuid", uuid);
        cJSON_AddStringToObject(json, "address", "127.0.0.1");
        cJSON_AddNumberToObject(json, "port", 443);
        construct(json, false);
    }
}

int main(void)
{
    initWLibc();
    logger_t *logger = loggerCreate();
    loggerSetLevel(logger, LOG_LEVEL_SILENT);
    setNetworkLogger(logger);
    twfRequire(globalstateInitializeSecureRandom() && frandGlobalInit(), "random initialization failed");
    frandInit();
    twfRequire(wCryptoGlobalInit() == kWCryptoOk, "crypto initialization failed");
    TEST_RUN_CASE(aliases);
    TEST_RUN_CASE(modes);
    TEST_RUN_CASE(strategies);
    TEST_RUN_CASE(invalidTypes);
    TEST_RUN_CASE(exactStrings);
    TEST_RUN_CASE(maturityOptions);
    wCryptoGlobalCleanup();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    networkloggerDestroy();
    return 0;
}
