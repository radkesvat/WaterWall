/* CTest: waterwall.authentication_numeric_settings_unit
 * Exercise the real constructors with exact JSON number and Boolean tokens. No node is
 * started: valid settings are inspected before timers or retention work begin,
 * and every constructor is destroyed with startup rollback. */
#include "AuthenticationClient/structure.h"
#include "fixtures/user_runtime.h"
/* The node-private size aliases share names; the state types do not. */
#define kTunnelStateSize kAuthenticationServerNumericTunnelStateSize
#define kLineStateSize   kAuthenticationServerNumericLineStateSize
#include "AuthenticationServer/structure.h"
#undef kTunnelStateSize
#undef kLineStateSize
#include "api/node_api.h"
#include "loggers/network_logger.h"
#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

typedef struct numeric_case_s
{
    const char *json;
    bool        positive;
    uint32_t    value;
} numeric_case_t;

static const numeric_case_t numeric_cases[] = {{NULL, true, 0},
                                               {"0", false, 0},
                                               {"1", true, 1},
                                               {"12345", true, 12345},
                                               {"2147483647", true, INT_MAX},
                                               {"-1", false, 0},
                                               {"-0.5", false, 0},
                                               {"0.5", false, 0},
                                               {"1.5", false, 0},
                                               {"1.0", false, 0},
                                               {"1e0", false, 0},
                                               {"\"1\"", false, 0},
                                               {"null", false, 0},
                                               {"true", false, 0},
                                               {"[]", false, 0},
                                               {"{}", false, 0},
                                               {"2147483648", false, 0},
                                               {"4294967296", false, 0},
                                               {"4294967297", false, 0},
                                               {"9223372036854775807", false, 0},
                                               {"18446744073709551616", false, 0}};

static void setNumberToken(cJSON *settings, const char *key, const char *json)
{
    cJSON_DeleteItemFromObjectCaseSensitive(settings, key);
    if (json != NULL)
    {
        cJSON *value = cJSON_Parse(json);
        require(value != NULL, "numeric fixture token did not parse");
        discard cJSON_AddItemToObject(settings, key, value);
    }
}

static void clientSettings(void)
{
    static const struct
    {
        const char *name;
        size_t      offset;
        uint32_t    fallback;
        bool        allows_zero;
    } fields[] = {{"ping-interval-ms",
                   offsetof(authenticationclient_tstate_t, ping_interval_ms),
                   kAuthenticationClientDefaultPingIntervalMs,
                   true},
                  {"pull-interval-ms",
                   offsetof(authenticationclient_tstate_t, pull_interval_ms),
                   kAuthenticationClientDefaultPullIntervalMs,
                   true},
                  {"push-interval-ms",
                   offsetof(authenticationclient_tstate_t, push_interval_ms),
                   kAuthenticationClientDefaultPushIntervalMs,
                   true},
                  {"reconnect-interval-ms",
                   offsetof(authenticationclient_tstate_t, reconnect_interval_ms),
                   kAuthenticationClientDefaultReconnectIntervalMs,
                   true},
                  {"request-timeout-ms",
                   offsetof(authenticationclient_tstate_t, request_timeout_ms),
                   kAuthenticationClientDefaultRequestTimeoutMs,
                   true},
                  {"max-pending-requests",
                   offsetof(authenticationclient_tstate_t, max_pending_requests),
                   kAuthenticationClientDefaultMaxPendingRequests,
                   false}};
    for (size_t field = 0; field < ARRAY_SIZE(fields); ++field)
    {
        for (size_t sample = 0; sample < ARRAY_SIZE(numeric_cases); ++sample)
        {
            const numeric_case_t *test = &numeric_cases[sample];
            char                  context[160];
            snprintf(context,
                     sizeof(context),
                     "client %s=%s",
                     fields[field].name,
                     test->json == NULL ? "<absent>" : test->json);
            testCaseSet(context);
            cJSON *settings = cJSON_Parse("{\"name\":\"edge\",\"secret\":\"fixture-secret\"}");
            require(settings != NULL, "client settings fixture did not parse");
            setNumberToken(settings, fields[field].name, test->json);
            char       name[] = "client", next[] = "transport";
            node_t     node     = {.name = name, .next = next, .node_settings_json = settings};
            tunnel_t  *t        = authenticationclientTunnelCreate(&node);
            const bool zero     = test->json != NULL && strcmp(test->json, "0") == 0;
            const bool accepted = test->positive || (zero && fields[field].allows_zero);
            require((t != NULL) == accepted, "client numeric setting acceptance mismatch");
            if (t != NULL)
            {
                const authenticationclient_tstate_t *ts = tunnelGetState(t);
                for (size_t other = 0; other < ARRAY_SIZE(fields); ++other)
                {
                    const uint32_t expected =
                        other == field && test->json != NULL ? test->value : fields[other].fallback;
                    const uint32_t actual = *(const uint32_t *) ((const uint8_t *) ts + fields[other].offset);
                    require(actual == expected, "client numeric setting rounded, wrapped or defaulted");
                }
                require(ts->pending_requests == NULL && ts->control_line == NULL,
                        "client constructor started runtime work");
                authenticationclientTunnelDestroy(t, wwLifecycleStartupRollback());
            }
            cJSON_Delete(settings);
        }
    }
}

static void clientBooleanAndDuplicateSettings(void)
{
    static const char *const invalid[] = {"\"verbose\":\"true\"",
                                          "\"verbose\":null",
                                          "\"verbose\":1",
                                          "\"verbose\":[]",
                                          "\"verbose\":false,\"verbose\":true",
                                          "\"ping-interval-ms\":1,\"ping-interval-ms\":2",
                                          "\"pull-interval-ms\":1,\"pull-interval-ms\":2",
                                          "\"push-interval-ms\":1,\"push-interval-ms\":2",
                                          "\"reconnect-interval-ms\":1,\"reconnect-interval-ms\":2",
                                          "\"request-timeout-ms\":1,\"request-timeout-ms\":2",
                                          "\"max-pending-requests\":1,\"max-pending-requests\":2",
                                          "\"sync-max-users\":1,\"sync-max-users\":2",
                                          "\"sync-max-bytes\":1,\"sync-max-bytes\":2",
                                          "\"traffic-multiplier\":1,\"traffic-multiplier\":2",
                                          "\"name\":\"duplicate\"",
                                          "\"secret\":\"duplicate\""};
    for (size_t i = 0; i < ARRAY_SIZE(invalid) + 2; ++i)
    {
        char        input[512];
        const char *fields = i < ARRAY_SIZE(invalid)    ? invalid[i]
                             : i == ARRAY_SIZE(invalid) ? "\"verbose\":false"
                                                        : "\"verbose\":true";
        snprintf(input, sizeof(input), "{\"name\":\"edge\",\"secret\":\"secret\",%s}", fields);
        testCaseSet(fields);
        cJSON *settings = cJSON_Parse(input);
        require(settings != NULL, "client settings shape fixture");
        char      name[] = "client", next[] = "transport";
        node_t    node = {.name = name, .next = next, .node_settings_json = settings};
        tunnel_t *t    = authenticationclientTunnelCreate(&node);
        require((t != NULL) == (i >= ARRAY_SIZE(invalid)), "client accepted loose Boolean or duplicate setting");
        if (t != NULL)
        {
            require(((authenticationclient_tstate_t *) tunnelGetState(t))->verbose == (i == ARRAY_SIZE(invalid) + 1),
                    "client Boolean setting was not preserved");
            authenticationclientTunnelDestroy(t, wwLifecycleStartupRollback());
        }
        cJSON_Delete(settings);
    }
}

static void requireDatabaseUnchanged(const char *path)
{
    static const char expected[]               = "{\"users\":[]}\n";
    char              actual[sizeof(expected)] = {0};
    FILE             *file                     = fopen(path, "rb");
    require(file != NULL, "database fixture disappeared");
    require(fread(actual, 1, sizeof(actual), file) == sizeof(expected) - 1 &&
                memcmp(actual, expected, sizeof(expected)) == 0 && fclose(file) == 0,
            "constructor changed database contents");
}

static void serverSettings(const char *database, const char *history)
{
    static const char *const fields[] = {
        "file-save-rate-ms", "session-idle-timeout-ms", "session-idle-timeout-ms", "normal-backups-count-limit"};
    for (size_t field = 0; field < ARRAY_SIZE(fields); ++field)
    {
        for (size_t sample = 0; sample < ARRAY_SIZE(numeric_cases); ++sample)
        {
            const numeric_case_t *test = &numeric_cases[sample];
            char                  context[160];
            snprintf(context,
                     sizeof(context),
                     "server %s%s=%s",
                     field == 2 ? "auth-clients[0]." : "",
                     fields[field],
                     test->json == NULL ? "<absent>" : test->json);
            testCaseSet(context);
            cJSON *settings = cJSON_Parse("{\"file-save-rate-ms\":10000,\"auth-clients\":[{\"name\":\"edge\","
                                          "\"secret\":\"fixture-secret\"}]}");
            require(settings != NULL, "server settings fixture did not parse");
            discard  cJSON_AddStringToObject(settings, "db-path", database);
            cJSON   *target   = settings;
            uint32_t fallback = 0;
            if (field == 1)
                fallback = kAuthenticationServerDefaultSessionIdleTimeoutMs;
            else if (field == 2)
            {
                /* The per-client default must inherit the configured server value. */
                fallback = 35000;
                discard cJSON_AddItemToObject(settings, "session-idle-timeout-ms", cJSON_CreateInt64(fallback));
                target = cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(settings, "auth-clients"), 0);
            }
            else if (field == 3)
            {
                fallback = kAuthenticationServerDefaultNormalBackupsCountLimit;
                discard cJSON_AddStringToObject(settings, "normal-backups", "daily");
                discard cJSON_AddStringToObject(settings, "normal-backups-path", history);
            }
            setNumberToken(target, fields[field], test->json);
            char       name[]   = "server";
            node_t     node     = {.name = name, .node_settings_json = settings};
            tunnel_t  *t        = authenticationserverTunnelCreate(&node);
            const bool accepted = test->positive && (test->json != NULL || field != 0);
            require((t != NULL) == accepted, "server numeric setting acceptance mismatch");
            if (t != NULL)
            {
                const authenticationserver_tstate_t *ts               = tunnelGetState(t);
                const uint32_t                       expected         = test->json == NULL ? fallback : test->value;
                const uint32_t                       expected_session = field == 1   ? expected
                                                                        : field == 2 ? 35000
                                                                                     : kAuthenticationServerDefaultSessionIdleTimeoutMs;
                require(ts->file_save_rate_ms == (field == 0 ? expected : 10000) &&
                            ts->session_idle_timeout_ms == expected_session && ts->auth_clients_count == 1 &&
                            ts->auth_clients[0].session_idle_timeout_ms == (field == 2 ? expected : expected_session) &&
                            ts->normal_backups_count_limit ==
                                (field == 3 ? expected : kAuthenticationServerDefaultNormalBackupsCountLimit),
                        "server numeric setting rounded, wrapped or defaulted");
                require(ts->save_timer == NULL && ts->session_expiry_timer == NULL,
                        "server constructor installed runtime timers");
                authenticationserverTunnelDestroy(t, wwLifecycleStartupRollback());
            }
            requireDatabaseUnchanged(database);
            if (field == 3 && accepted)
                require(rmdir(history) == 0, "valid retention fixture did not create an empty history directory");
            require(access(history, F_OK) != 0 && errno == ENOENT,
                    "rejected retention setting created its history directory");
            cJSON_Delete(settings);
        }
    }
}

static void serverSnapshotSettings(const char *database)
{
    static const char *const keys[]   = {"snapshot-max-bytes", "snapshot-idle-timeout-ms"};
    static const char *const values[] = {"0", "null", "1.5", "\"1\"", "true", "1", "4096"};
    for (size_t key = 0; key < ARRAY_SIZE(keys); ++key)
        for (size_t sample = 0; sample < ARRAY_SIZE(values) + 1; ++sample)
        {
            testCaseSet(keys[key]);
            cJSON  *settings = cJSON_Parse("{\"file-save-rate-ms\":10000,\"auth-clients\":[{\"name\":\"edge\","
                                           "\"secret\":\"secret\"}]}");
            discard cJSON_AddStringToObject(settings, "db-path", database);
            if (sample < ARRAY_SIZE(values))
                discard cJSON_AddItemToObject(settings, keys[key], cJSON_Parse(values[sample]));
            else
            {
                discard cJSON_AddNumberToObject(settings, keys[key], 1);
                discard cJSON_AddNumberToObject(settings, keys[key], 2);
            }
            char      name[] = "snapshot-settings";
            node_t    node   = {.name = name, .node_settings_json = settings};
            tunnel_t *t      = authenticationserverTunnelCreate(&node);
            require((t != NULL) == (sample == 5 || sample == 6),
                    "snapshot setting accepted invalid or duplicate input");
            if (t != NULL)
                authenticationserverTunnelDestroy(t, wwLifecycleStartupRollback());
            cJSON_Delete(settings);
            requireDatabaseUnchanged(database);
        }
}

static void serverBooleanSettings(const char *database)
{
    static const char *const fields[] = {"verbose", "allow-stats-push", "allow-user-pull", "allow-user-write"};
    static const struct
    {
        const char *json;
        const char *duplicate;
        bool        accepted;
        bool        value;
    } cases[] = {{NULL, NULL, true, false},
                 {"false", NULL, true, false},
                 {"true", NULL, true, true},
                 {"\"true\"", NULL, false, false},
                 {"\"false\"", NULL, false, false},
                 {"0", NULL, false, false},
                 {"1", NULL, false, false},
                 {"null", NULL, false, false},
                 {"[]", NULL, false, false},
                 {"{}", NULL, false, false},
                 {"false", "true", false, false},
                 {"true", "false", false, false},
                 {"false", "false", false, false},
                 {"true", "true", false, false}};
    for (size_t field = 0; field < ARRAY_SIZE(fields); ++field)
        for (size_t sample = 0; sample < ARRAY_SIZE(cases); ++sample)
        {
            char context[192];
            snprintf(context,
                     sizeof(context),
                     "server %s%s=%s%s%s",
                     field == 0 ? "" : "auth-clients[1].",
                     fields[field],
                     cases[sample].json == NULL ? "<absent>" : cases[sample].json,
                     cases[sample].duplicate == NULL ? "" : ", duplicate=",
                     cases[sample].duplicate == NULL ? "" : cases[sample].duplicate);
            testCaseSet(context);
            cJSON *settings =
                cJSON_Parse("{\"verbose\":true,\"file-save-rate-ms\":10000,\"auth-clients\":["
                            "{\"name\":\"first\",\"secret\":\"first-secret\",\"allow-stats-push\":true,"
                            "\"allow-user-pull\":false,\"allow-user-write\":true},"
                            "{\"name\":\"second\",\"secret\":\"second-secret\",\"allow-stats-push\":false,"
                            "\"allow-user-pull\":true,\"allow-user-write\":false}]}");
            require(settings != NULL, "server Boolean settings fixture did not parse");
            discard cJSON_AddStringToObject(settings, "db-path", database);
            cJSON  *target = field == 0
                                 ? settings
                                 : cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(settings, "auth-clients"), 1);
            setNumberToken(target, fields[field], cases[sample].json);
            if (cases[sample].duplicate != NULL)
                discard cJSON_AddItemToObject(target, fields[field], cJSON_Parse(cases[sample].duplicate));
            char      name[] = "server-booleans";
            node_t    node   = {.name = name, .node_settings_json = settings};
            tunnel_t *t      = authenticationserverTunnelCreate(&node);
            require((t != NULL) == cases[sample].accepted, "server accepted loose Boolean or duplicate setting");
            if (t != NULL)
            {
                const authenticationserver_tstate_t *ts = tunnelGetState(t);
                require(ts->verbose == (field == 0 ? cases[sample].value : true) && ts->auth_clients_count == 2,
                        "server Boolean value or producer count changed");
                for (size_t producer = 0; producer < 2; ++producer)
                {
                    const authenticationserver_auth_client_t *client = &ts->auth_clients[producer];
                    const bool stats = producer == 1 && field == 1 ? cases[sample].value : producer == 0;
                    const bool pull  = producer == 1 && field == 2 ? cases[sample].value : producer == 1;
                    const bool write = producer == 1 && field == 3 ? cases[sample].value : producer == 0;
                    require(client->allow_stats_push == stats && client->allow_user_pull == pull &&
                                client->allow_user_write == write,
                            "server Boolean setting changed sibling permissions");
                }
                require(ts->save_timer == NULL && ts->session_expiry_timer == NULL && ts->sessions_count == 0,
                        "server Boolean constructor started runtime work");
                authenticationserverTunnelDestroy(t, wwLifecycleStartupRollback());
            }
            requireDatabaseUnchanged(database);
            cJSON_Delete(settings);
        }
}

int main(void)
{
    testCaseSet("authentication numeric settings");
    require(createNetworkLogger(NULL, false) != NULL && userTestRuntimeInitialize(),
            "numeric fixture initialization failed");
    /* Registration validates the client API's worker 0. No loops or lines are
     * required until Start, which this constructor-only fixture never invokes. */
    worker_t worker         = {.wid = 0};
    GSTATE.workers          = &worker;
    GSTATE.workers_count    = 1;
    GSTATE.flag_initialized = true;
    nodeApiRegistryInitialize();
    char directory[] = "/tmp/waterwall-auth-numeric-XXXXXX";
    require(mkdtemp(directory) != NULL, "numeric fixture directory creation failed");
    char database[256], history[256];
    snprintf(database, sizeof(database), "%s/users.json", directory);
    snprintf(history, sizeof(history), "%s/history", directory);
    FILE *file = fopen(database, "wb");
    require(file != NULL && fputs("{\"users\":[]}\n", file) >= 0 && fclose(file) == 0,
            "numeric database fixture creation failed");
    clientSettings();
    clientBooleanAndDuplicateSettings();
    serverSettings(database, history);
    serverSnapshotSettings(database);
    serverBooleanSettings(database);
    testCaseSet("authentication numeric settings cleanup");
    require(unlink(database) == 0 && rmdir(directory) == 0, "numeric fixture directory cleanup failed");
    nodeApiRegistryDestroy();
    GSTATE.flag_initialized = false;
    GSTATE.workers          = NULL;
    GSTATE.workers_count    = 0;
    userTestRuntimeCleanup();
    networkloggerDestroy();
    return 0;
}
