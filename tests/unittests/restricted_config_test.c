#include "node_builder/config_policy.h"
#include "node_builder/node_library.h"
/* Exercise the checked arithmetic without attempting a SIZE_MAX allocation. */
#include "node_builder/config_file.c"

#ifdef WW_TEST_WRAP_DLOPEN
static unsigned int loader_calls;
void               *__wrap_dlopen(const char *path, int flags);
void               *__wrap_dlopen(const char *path, int flags)
{
    discard path;
    discard flags;
    ++loader_calls;
    return NULL;
}
#endif

static void require(bool ok, const char *message)
{
    if (! ok)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void expectParse(const char *text, bool valid)
{
    cJSON *json = configPolicyParse(text, strlen(text));
    require((json != NULL) == valid, text);
    cJSON_Delete(json);
}

static void testReads(size_t limit)
{
    for (int delta = -1; delta <= 1; ++delta)
    {
        size_t size  = (size_t) ((int64_t) limit + delta);
        FILE  *input = tmpfile();
        require(input != NULL, "temporary read fixture");
        char block[4096];
        memset(block, ' ', sizeof(block));
        size_t remaining = size;
        while (remaining != 0)
        {
            size_t count = min(remaining, sizeof(block));
            require(fwrite(block, 1, count, input) == count, "write read fixture");
            remaining -= count;
        }
        rewind(input);
        size_t length = 0;
        char  *data   = configPolicyRead(input, limit, &length);
        require((data != NULL) == (delta <= 0), "read limit boundary");
        if (data != NULL)
            require(length == size && data[length] == '\0', "read length");
        memoryFree(data);
        fclose(input);
    }
}

int main(int argc, char **argv)
{
    initWLibc();
    createInternalLogger(NULL, true);
    if (argc == 2 && strcmp(argv[1], "--parse-json") == 0)
    {
        size_t size   = 0;
        char  *input  = configPolicyRead(stdin, WW_HOST_NODE_JSON_LIMIT, &size);
        cJSON *parsed = input != NULL ? configPolicyParse(input, size) : NULL;
        bool   valid  = parsed != NULL;
        cJSON_Delete(parsed);
        memoryFree(input);
        internaloggerDestroy();
        return valid ? 0 : 1;
    }
    char  *buffer = memoryAllocate(1);
    size_t length = SIZE_MAX - 2, capacity = 1;
    require(! appendJsonChunk(&buffer, &length, &capacity, "ab", 2), "overflow rejected before copy");
    require(length == SIZE_MAX - 2 && capacity == 1, "overflow preserves caller state");
    memoryFree(buffer);

#ifdef WW_TEST_WRAP_DLOPEN
    nodelibrarySetSearchPath("configured-untrusted-path");
    require(setenv("WW_LIBS_PATH", "environment-untrusted-path", 1) == 0, "library environment");
    require(nodelibraryLoadByTypeHash(43).hash_type == 0 && loader_calls != 0, "ordinary CLI reaches loader");
    loader_calls = 0;
#endif
    configPolicyRestrict();
    require(configPolicyIsRestricted(), "restricted policy enabled");
    const char *valid[] = {"{}",
                           "[]",
                           "0",
                           "-1.25e+2",
                           "true",
                           "null",
                           "\"\\\\u0000\"",
                           "{\"a\":1,\"A\":2}",
                           "{\"\\u0061\":1}",
                           "\"\\ud83d\\ude00\"",
                           "\"\xc3\xa9\"",
                           " {\"x\":[false,0.1]} \r\n"};
    for (size_t i = 0; i < ARRAY_SIZE(valid); ++i)
        expectParse(valid[i], true);
    const char *invalid[] = {"",
                             "{}secret",
                             "{\"a\":1,\"\\u0061\":2}",
                             "\"\\u0000\"",
                             "{\"\\u0000\":1}",
                             "\"\\uZZZZ\"",
                             "\"\\ud800\"",
                             "\"\\udc00\"",
                             "\"\xc0\xaf\"",
                             "\"\xed\xa0\x80\"",
                             "\"\xf4\x90\x80\x80\"",
                             "\"\xe2\x82\"",
                             "\"\x80\"",
                             "[01]",
                             "1.",
                             "1e+",
                             "[1+2]",
                             "1e9999",
                             "\v{}",
                             "\"line\nfeed\"",
                             "\xef\xbb\xbf{}",
                             "[true,]",
                             "{\"a\":0,}"};
    for (size_t i = 0; i < ARRAY_SIZE(invalid); ++i)
        expectParse(invalid[i], false);
    const char embedded[] = "{}\0secret";
    require(! configPolicyCheckEncoding(embedded, sizeof(embedded) - 1), "embedded NUL");

    char nested[2 * (WW_HOST_JSON_DEPTH_LIMIT + 1) + 1];
    for (size_t depth = WW_HOST_JSON_DEPTH_LIMIT; depth <= WW_HOST_JSON_DEPTH_LIMIT + 1; ++depth)
    {
        memset(nested, '[', depth);
        memset(nested + depth, ']', depth);
        nested[2 * depth] = '\0';
        expectParse(nested, depth == WW_HOST_JSON_DEPTH_LIMIT);
    }
    testReads(WW_HOST_CORE_JSON_LIMIT);
    testReads(WW_HOST_NODE_JSON_LIMIT);

    char *comments = stripJsonLineComments("{\"url\":\"https://x\",//comment\n\"x\":1}");
    require(comments != NULL, "comments accepted");
    expectParse(comments, true);
    memoryFree(comments);
    const char *source = "{\"variab\\u006ces\":{\"a\":\"resolved\"},\"x\":$a$,\"quoted\":\"$a$\"}";
    bool        ok;
    cJSON      *vars = parseVariablesObject(source, "fixture", &ok);
    require(ok && vars != NULL, "escaped variables key");
    char *resolved = substituteVariables(source, vars, "fixture");
    require(resolved != NULL, "substitution succeeds");
    cJSON *json = configPolicyParse(resolved, strlen(resolved));
    require(json != NULL, "resolved strict parse");
    require(strcmp(cJSON_GetObjectItemCaseSensitive(json, "x")->valuestring, "resolved") == 0, "resolved value");
    require(strcmp(cJSON_GetObjectItemCaseSensitive(json, "quoted")->valuestring, "$a$") == 0, "quoted placeholder");
    memoryFree(resolved);
    cJSON_Delete(json);
    cJSON_Delete(vars);

    char *large = memoryAllocate(WW_HOST_NODE_JSON_LIMIT + 1);
    memset(large, 'x', WW_HOST_NODE_JSON_LIMIT);
    large[WW_HOST_NODE_JSON_LIMIT] = '\0';
    buffer                         = memoryAllocate(1);
    buffer[0]                      = '\0';
    length                         = 0;
    capacity                       = 1;
    require(appendJsonChunk(&buffer, &length, &capacity, large, WW_HOST_NODE_JSON_LIMIT), "exact expansion limit");
    require(! appendJsonChunk(&buffer, &length, &capacity, "x", 1), "expansion limit plus one");
    memoryFree(buffer);
    large[3 * 1024 * 1024] = '\0';
    vars                   = cJSON_CreateObject();
    require(cJSON_AddStringToObject(vars, "large", large) != NULL, "large replacement");
    resolved = substituteVariables("[$large$,$large$,$large$]", vars, "fixture");
    require(resolved == NULL, "repeated replacement quota");
    cJSON_Delete(vars);
    memoryFree(large);

    node_t builtin = {.type = stringDuplicate("RestrictedBuiltin"), .hash_type = 42};
    nodelibraryRegister(builtin);
    require(nodelibraryLoadByTypeHash(42).hash_type == 42, "built-in preserved");
    require(nodelibraryLoadByTypeHash(43).hash_type == 0, "external node rejected");
#ifdef WW_TEST_WRAP_DLOPEN
    require(loader_calls == 0, "restricted lookup never calls dlopen across any search path");
#endif
    nodelibraryCleanup();
    internaloggerDestroy();
    puts("restricted config tests passed");
    return 0;
}
