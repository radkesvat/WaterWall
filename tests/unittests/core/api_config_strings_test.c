/* Preserve raw lexical evidence before cJSON truncates embedded NUL. Only API
 * settings reject immediately; selector-name evidence is deferred until an API
 * endpoint is configured globally. Unrelated permissive configuration remains
 * unchanged. CTest: waterwall.api_config_strings_unit. */
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
            "scoped API settings lexical result differs");
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

int main(void)
{
    TEST_RUN_CASE(testSelectorEvidence);
    TEST_RUN_CASE(testSettingsScope);
    TEST_RUN_CASE(testVariableEvidence);
    return 0;
}
