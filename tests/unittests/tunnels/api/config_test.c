/* APIServer startup policy and complete request/response geometry. Pure settings
 * parsing, including partial-construction cleanup; NodeManager preparation and
 * raw lexical token/name evidence have separate core fixtures.
 * CTest: waterwall.apiserver_config_unit. */
#include "APIServer/interface.h"
#include "APIServer/structure.h"

#include "test_assert.h"

#define require(c, m) TEST_REQUIRE(TEST_FAILURE_EXIT, c, m)

static const char token[] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static cJSON     *validSettings(void)
{
    char text[1024];
    snprintf(text,
             sizeof(text),
             "{\"clients\":[{\"name\":\"monitor\",\"token\":\"%s\",\"allow\":["
             "{\"config\":\"one\",\"node\":\"auth\",\"operations\":[\"status\"]}]}]}",
             token);
    return cJSON_Parse(text);
}

static void check(cJSON *settings, bool expected)
{
    require(settings != NULL, "fixture JSON");
    apiserver_tstate_t ts = {0};
    require(apiserverLoadSettings(&ts, settings) == expected, "settings validation");
    if (expected)
    {
        require(ts.limits.max_request_envelope == 1048576 && ts.limits.max_response_envelope == 1048576,
                "default envelope limits");
        require(ts.limits.max_line_memory == 8388608 && ts.limits.max_memory == 67108864, "default memory geometry");
    }
    apiserverFreeSettings(&ts);
    require(ts.clients == NULL, "partial policy cleanup");
    cJSON_Delete(settings);
}

static cJSON *client(cJSON *settings)
{
    return cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(settings, "clients"), 0);
}

static cJSON *permission(cJSON *settings)
{
    return cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(client(settings), "allow"), 0);
}

static void settingsValidation(void)
{
    check(validSettings(), true);
    static const char *const invalid[] = {"null", "[]", "{}", "{\"clients\":null}", "{\"clients\":[]}"};
    for (size_t i = 0; i < ARRAY_SIZE(invalid); ++i)
        check(cJSON_Parse(invalid[i]), false);
    cJSON *json = validSettings();
    cJSON_AddBoolToObject(json, "read_only", true);
    check(json, false);
    json = validSettings();
    cJSON_DeleteItemFromObjectCaseSensitive(client(json), "token");
    check(json, false);
    json = validSettings();
    cJSON_ReplaceItemInObjectCaseSensitive(client(json), "token", cJSON_CreateString("abcd"));
    check(json, false);
    json = validSettings();
    cJSON_ReplaceItemInObjectCaseSensitive(client(json), "name", cJSON_CreateString(""));
    check(json, false);
    json = validSettings();
    cJSON_ReplaceItemInObjectCaseSensitive(client(json), "allow", cJSON_CreateArray());
    check(json, false);
    static const char *const keys[] = {"config", "node", "operations"};
    for (size_t i = 0; i < ARRAY_SIZE(keys); ++i)
    {
        json = validSettings();
        cJSON_DeleteItemFromObjectCaseSensitive(permission(json), keys[i]);
        check(json, false);
    }
    json = validSettings();
    cJSON_ReplaceItemInObjectCaseSensitive(permission(json), "config", cJSON_CreateString("*"));
    check(json, false);
    json              = validSettings();
    cJSON *operations = cJSON_GetObjectItemCaseSensitive(permission(json), "operations");
    cJSON_ReplaceItemInArray(operations, 0, cJSON_CreateString("*"));
    check(json, false);
    json = validSettings();
    cJSON_AddStringToObject(client(json), "token", token);
    check(json, false);
    json        = validSettings();
    cJSON *copy = cJSON_Duplicate(client(json), true);
    cJSON_ReplaceItemInObjectCaseSensitive(
        copy, "token", cJSON_CreateString("1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    cJSON_AddItemToArray(cJSON_GetObjectItemCaseSensitive(json, "clients"), copy);
    check(json, false); /* Duplicate principal, distinct tokens. */
    json = validSettings();
    copy = cJSON_Duplicate(client(json), true);
    cJSON_ReplaceItemInObjectCaseSensitive(copy, "name", cJSON_CreateString("other"));
    cJSON_ReplaceItemInObjectCaseSensitive(
        copy, "token", cJSON_CreateString("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"));
    cJSON_AddItemToArray(cJSON_GetObjectItemCaseSensitive(json, "clients"), copy);
    check(json, false); /* Decoded token uniqueness ignores hexadecimal case. */
}

static void limitValidation(void)
{
    static const char *const limits[] = {"max_request_envelope",
                                         "max_response_envelope",
                                         "max_input_bytes",
                                         "max_line_memory",
                                         "max_input_fragments",
                                         "max_queued_requests",
                                         "max_sessions",
                                         "max_jobs",
                                         "handler_working_memory",
                                         "max_memory",
                                         "frame_timeout_ms",
                                         "request_timeout_ms",
                                         "output_timeout_ms",
                                         "idle_timeout_ms"};
    for (size_t i = 0; i < ARRAY_SIZE(limits); ++i)
    {
        for (unsigned variant = 0; variant < 4; ++variant)
        {
            cJSON *json  = validSettings();
            cJSON *value = variant == 0   ? cJSON_CreateInt64(0)
                           : variant == 1 ? cJSON_CreateInt64(-1)
                           : variant == 2 ? cJSON_CreateBool(true)
                                          : cJSON_CreateNumber(1.5);
            cJSON_AddItemToObject(json, limits[i], value);
            check(json, false);
        }
    }
    static const char *const geometry[] = {
        "max_response_envelope", "max_input_bytes", "max_line_memory", "max_memory", "handler_working_memory"};
    for (size_t i = 0; i < ARRAY_SIZE(geometry); ++i)
    {
        cJSON *json = validSettings();
        cJSON_AddItemToObject(json, geometry[i], cJSON_CreateInt64(1));
        check(json, false);
    }
}

static void gatewayIdentityValidation(void)
{
    char too_long[258];
    memset(too_long, 'g', sizeof(too_long) - 1);
    too_long[sizeof(too_long) - 1] = '\0';
    const char *invalid[]          = {NULL, "", too_long, "\xff"};
    for (size_t i = 0; i < ARRAY_SIZE(invalid); ++i)
    {
        node_t node = {.name = (char *) invalid[i]};
        require(apiserverTunnelCreate(&node) == NULL, "invalid gateway identity was admitted");
    }
}

int main(void)
{
    TEST_RUN_CASE(settingsValidation);
    TEST_RUN_CASE(limitValidation);
    TEST_RUN_CASE(gatewayIdentityValidation);
    return 0;
}
