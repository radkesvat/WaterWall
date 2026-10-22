/* Preserve raw lexical evidence for API settings and deferred selector checks.
 * Variable substitution retains malformed string evidence for any opt-in exact
 * field consumer. Unrelated permissive configuration remains unchanged.
 * CTest: waterwall.api_config_strings_unit. */
#include "wwapi.h"

#include "test_assert.h"

#include "node_builder/config_file.c" // NOLINT: verify scoped lexical capture before source discard

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static void inspect(const char *source, bool valid_settings, bool invalid_selectors)
{
    cJSON *tree = cJSON_Parse(source);
    require(tree != NULL, "fixture must be accepted by the existing host parser");
    config_file_t config = {0};
    require(apiConfigCaptureLexicalFacts(&config, source, strlen(source), tree) == valid_settings,
            "scoped node settings lexical result differs");
    require(config.api_selector_strings_invalid == invalid_selectors, "selector lexical evidence was lost");
    cJSON_Delete(tree);
}

static void testSelectorEvidence(void)
{
    inspect("{\"name\":\"edge\",\"nodes\":[{\"name\":\"auth\",\"type\":\"AuthenticationClient\"}]}", true, false);
    inspect("{\"name\":\"edge\\u0000suffix\",\"nodes\":[{\"name\":\"auth\"}]}", true, true);
    inspect("{\"name\\u0000suffix\":\"edge\",\"nodes\":[{\"name\":\"auth\"}]}", true, true);
    inspect("{\"name\":\"edge\",\"nodes\":[{\"name\":\"auth\\u0000suffix\"}]}", true, true);
    inspect("{\"name\":\"edge\",\"nodes\":[{\"name\\u0000suffix\":\"auth\"}]}", true, true);
    inspect("{\"name\":\"edge\",\"nodes\\u0000suffix\":[{\"name\":\"auth\"}]}", true, true);
    inspect("{\"name\":\"\xc0\xaf\",\"nodes\":[{\"name\":\"auth\"}]}", true, true);
    inspect("{\"\\u006eame\":\"edge\",\"nodes\":[{\"name\":\"literal\\\\u0000\"}]}", true, false);
}

static void testSettingsScope(void)
{
    inspect("{\"name\":\"edge\",\"nodes\":[{\"name\":\"api\",\"type\":\"APIServer\","
            "\"settings\":{\"clients\":[{\"token\":\"abc\\u0000suffix\"}]}}]}",
            false,
            false);
    inspect("{\"name\":\"edge\",\"nodes\":[{\"name\":\"api\",\"type\":\"APIServer\","
            "\"settings\\u0000suffix\":{}}]}",
            false,
            false);
    inspect("{\"name\":\"edge\",\"nodes\":[{\"name\":\"api\",\"type\":\"APIServer\\u0000suffix\","
            "\"settings\":{}}]}",
            false,
            false);
    inspect("{\"name\":\"edge\",\"nodes\":[{\"name\":\"api\",\"type\":\"APIServer\","
            "\"settings\":{\"client\":\"\xc0\xaf\"}}]}",
            false,
            false);
    inspect("{\"name\":\"edge\",\"author\":\"ignored\\u0000suffix\",\"nodes\":[{\"name\":\"other\","
            "\"type\":\"Other\",\"settings\":{\"ignored\":\"\\u0000\",\"duplicate\":1,\"duplicate\":2}}]}",
            true,
            false);
    inspect("{\"name\":\"edge\",\"nodes\":[{\"name\":\"api\",\"type\":\"APIServer\","
            "\"settings\":{\"clients\":[{\"token\":\"abc\",\"allow\":[{\"node\":\"auth\"}]}]}}]}",
            true,
            false);
}

static void testVariableEvidence(void)
{
    const char *source       = "{\"name\":\"edge\",\"variables\":{\"token\":\"abc\\u0000suffix\"},"
                               "\"nodes\":[{\"name\":\"api\",\"type\":\"APIServer\",\"settings\":{\"token\":$token$}}]}";
    bool        variables_ok = false;
    cJSON      *variables    = parseVariablesObject(source, "api-config-strings", &variables_ok);
    require(variables_ok && variables != NULL, "variable fixture failed to parse");
    char *resolved = substituteVariables(source, variables, "api-config-strings");
    require(resolved != NULL && strstr(resolved, "abc\\u0000suffix") != NULL,
            "variable serialization erased malformed credential evidence");
    inspect(resolved, false, false);
    memoryFree(resolved);
    cJSON_Delete(variables);
}

static void testGenericVariableEvidence(void)
{
    const struct
    {
        const char *source;
        const char *field;
        bool        exact;
    } cases[] = {
        {"{\"variables\":{\"value\":\"bad\\u0000suffix\"},\"settings\":{\"value\":$value$}}", "value", false},
        {"{\"variables\":{\"value\":\"bad\xc0\xaf\"},\"settings\":{\"value\":$value$}}", "value", false},
        {"{\"variables\":{\"key\":\"enabled\\u0000suffix\"},\"settings\":{$key$:false}}", "enabled", false},
        {"{\"variables\":{\"key\":\"enabled\"},\"settings\":{$key$:false}}", "enabled", true},
        {"{\"variables\":{\"object\":{\"value\":\"bad\\u0000suffix\"}},\"settings\":$object$}", "value", false},
        {"{\"variables\":{\"object\":{\"enabled\\u0000suffix\":false}},\"settings\":$object$}", "enabled", false},
        {"{\"variables\":{\"object\":{\"value\":\"literal\\\\u0000\"}},\"settings\":$object$}", "value", true},
        {"{\"variables\":{\"object\":{\"value\":\"caf\xc3\xa9\"}},\"settings\":$object$}", "value", true},
    };
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        bool   variables_ok = false;
        cJSON *variables    = parseVariablesObject(cases[i].source, "generic-config-strings", &variables_ok);
        require(variables_ok && variables != NULL, "generic variable fixture failed to parse");
        char *resolved = substituteVariables(cases[i].source, variables, "generic-config-strings");
        require(resolved != NULL, "generic variable substitution failed");
        cJSON *tree = cJSON_Parse(resolved);
        require(tree != NULL, "resolved variable fixture failed to parse");
        require(jsonObjectFieldStringsAreExact(cJSON_GetObjectItemCaseSensitive(tree, "settings"), cases[i].field) ==
                    cases[i].exact,
                "substitution changed exact field evidence");
        cJSON_Delete(tree);
        memoryFree(resolved);
        cJSON_Delete(variables);
    }
}

int main(void)
{
    TEST_RUN_CASE(testSelectorEvidence);
    TEST_RUN_CASE(testSettingsScope);
    TEST_RUN_CASE(testVariableEvidence);
    TEST_RUN_CASE(testGenericVariableEvidence);
    return 0;
}
