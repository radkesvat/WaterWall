/*
 * Covers: strict API envelopes and exact response measurement/serialization.
 * Setup: real APIServer codec, immutable test-only descriptors, owned bytes.
 * Checks: malicious metadata/schema, opaque text/binary fidelity, fixed gateway
 * errors, node failures, empty and >65 KiB results, output boundary guards.
 * Limits: Stream parsing, worker dispatch and transport limits are separate
 * fixtures; these calls receive one complete envelope, excluding its prefix.
 * CTest: waterwall.apiserver_codec_unit
 */
#include "APIServer/codec.h"
#include "test_assert.h"
#include "wwapi.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static const char token[] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

static const node_api_operation_t text_operation = {
    .name = "private-text", .response_content_type = "application/json", .response_encoding = kNodeApiEncodingUtf8};
static const node_api_operation_t binary_operation = {.name                  = "private-binary",
                                                      .response_content_type = "application/octet-stream",
                                                      .response_encoding     = kNodeApiEncodingBase64};

static cJSON *requestJson(const char *body)
{
    cJSON *root     = cJSON_CreateObject();
    cJSON *auth     = cJSON_AddObjectToObject(root, "auth");
    cJSON *selector = cJSON_AddObjectToObject(root, "selector");
    cJSON_AddStringToObject(root, "id", "req-42");
    cJSON_AddStringToObject(auth, "client", "monitor");
    cJSON_AddStringToObject(auth, "token", token);
    cJSON_AddStringToObject(selector, "config", "edge");
    cJSON_AddStringToObject(selector, "node", "auth-client");
    cJSON_AddStringToObject(root, "operation", "status");
    cJSON_AddStringToObject(root, "content_type", "application/json");
    cJSON_AddStringToObject(root, "body_encoding", "utf8");
    cJSON_AddStringToObject(root, "body", body);
    return root;
}

static api_request_t parseJson(cJSON *json)
{
    char         *encoded = cJSON_PrintUnformatted(json);
    api_request_t parsed  = {0};
    apiserverRequestParse(&parsed, encoded, strlen(encoded));
    cJSON_free(encoded);
    return parsed;
}

static void rejected(cJSON *json, const char *error)
{
    api_request_t parsed = parseJson(json);
    require(parsed.error && strcmp(parsed.error, error) == 0, "Malformed request used an unexpected gateway code");
    require(parsed.close, "Malformed request did not request terminal closure");
    memoryFree(parsed.body);
    cJSON_Delete(json);
}

static void rawRejected(const char *bytes, size_t size)
{
    api_request_t parsed = {0};
    apiserverRequestParse(&parsed, bytes, size);
    require(parsed.error && strcmp(parsed.error, "invalid_request") == 0, "Invalid lexical envelope was accepted");
    require(parsed.close, "Invalid lexical envelope did not request closure");
    memoryFree(parsed.body);
}

static void validBodies(void)
{
    static const char body[] = " \n{\"integer\":18446744073709551615,\"text\":\"\xc3\xa9\"}\t ";
    cJSON            *json   = requestJson(body);
    api_request_t     parsed = parseJson(json);
    require(! parsed.error && ! parsed.close, "Valid UTF-8 request was rejected");
    require(parsed.body_size == sizeof(body) - 1 && memcmp(parsed.body, body, sizeof(body) - 1) == 0,
            "Gateway normalized opaque text or changed exact large integer bytes");
    require(strcmp(parsed.id, "req-42") == 0 && strcmp(parsed.config, "edge") == 0 &&
                strcmp(parsed.node, "auth-client") == 0,
            "Envelope metadata changed");
    memoryFree(parsed.body);
    cJSON_Delete(json);

    json = requestJson("AH+A/w==");
    cJSON_ReplaceItemInObjectCaseSensitive(json, "body_encoding", cJSON_CreateString("base64"));
    cJSON_DeleteItemFromObjectCaseSensitive(cJSON_GetObjectItemCaseSensitive(json, "selector"), "config");
    parsed                        = parseJson(json);
    static const uint8_t binary[] = {0, 0x7f, 0x80, 0xff};
    require(! parsed.error && parsed.config[0] == '\0', "Canonical binary or unqualified selector was rejected");
    require(parsed.body_size == sizeof(binary) && memcmp(parsed.body, binary, sizeof(binary)) == 0,
            "Decoded binary request lost NUL or non-UTF-8 bytes");
    memoryFree(parsed.body);
    cJSON_Delete(json);

    for (size_t i = 0; i < 2; ++i)
    {
        json = requestJson("");
        cJSON_ReplaceItemInObjectCaseSensitive(json, "body_encoding", cJSON_CreateString(i ? "base64" : "utf8"));
        parsed = parseJson(json);
        require(! parsed.error && parsed.body_size == 0, "Empty gateway body was rejected");
        memoryFree(parsed.body);
        cJSON_Delete(json);
    }
}

static void invalidSchema(void)
{
    static const char *const fields[] = {
        "id", "auth", "selector", "operation", "content_type", "body_encoding", "body"};
    for (size_t i = 0; i < sizeof(fields) / sizeof(*fields); ++i)
    {
        cJSON *json = requestJson("{}");
        cJSON_DeleteItemFromObjectCaseSensitive(json, fields[i]);
        rejected(json, i == 1 ? "unauthorized" : "invalid_request");
        json = requestJson("{}");
        cJSON_ReplaceItemInObjectCaseSensitive(json, fields[i], cJSON_CreateNull());
        rejected(json, i == 1 ? "unauthorized" : "invalid_request");
        json = requestJson("{}");
        cJSON_ReplaceItemInObjectCaseSensitive(json, fields[i], cJSON_CreateNumber(7));
        rejected(json, i == 1 ? "unauthorized" : "invalid_request");
    }
    static const char *const parents[] = {NULL, "auth", "selector"};
    for (size_t i = 0; i < 3; ++i)
    {
        cJSON *json = requestJson("{}");
        cJSON *into = parents[i] ? cJSON_GetObjectItemCaseSensitive(json, parents[i]) : json;
        cJSON_AddStringToObject(into, "unknown", "value");
        rejected(json, "invalid_request");
    }
    for (size_t i = 0; i < 3; ++i)
    {
        cJSON *json = requestJson("{}");
        cJSON *into = parents[i] ? cJSON_GetObjectItemCaseSensitive(json, parents[i]) : json;
        cJSON_AddStringToObject(into, i == 0 ? "id" : (i == 1 ? "client" : "node"), "duplicate");
        rejected(json, "invalid_request");
    }
    cJSON *json = requestJson("{}");
    cJSON_AddItemToObject(json, "unknown", cJSON_CreateArray());
    cJSON *array = cJSON_GetObjectItemCaseSensitive(json, "unknown");
    cJSON_AddItemToArray(array, cJSON_CreateArray());
    cJSON_AddItemToArray(array->child, cJSON_CreateArray());
    rejected(json, "invalid_request");

    json = requestJson("{}");
    for (size_t i = 0; i < 50; ++i)
    {
        char key[32];
        snprintf(key, sizeof(key), "key-%zu", i);
        cJSON_AddBoolToObject(json, key, true);
    }
    rejected(json, "invalid_request");
}

static void labelsAndTokens(void)
{
    static const struct
    {
        const char *parent;
        const char *field;
        size_t      maximum;
        const char *error;
    } labels[] = {{NULL, "id", 64, "invalid_request"},
                  {"selector", "config", 256, "invalid_request"},
                  {"selector", "node", 256, "invalid_request"},
                  {NULL, "operation", 64, "invalid_request"},
                  {NULL, "content_type", 128, "invalid_request"},
                  {"auth", "client", 256, "unauthorized"}};
    for (size_t i = 0; i < sizeof(labels) / sizeof(*labels); ++i)
    {
        char value[258];
        memset(value, 'a', labels[i].maximum + 1);
        value[labels[i].maximum + 1] = '\0';
        cJSON *json                  = requestJson("{}");
        cJSON *into = labels[i].parent ? cJSON_GetObjectItemCaseSensitive(json, labels[i].parent) : json;
        cJSON_ReplaceItemInObjectCaseSensitive(into, labels[i].field, cJSON_CreateString(value));
        rejected(json, labels[i].error);

        value[labels[i].maximum] = '\0';
        json                     = requestJson("{}");
        into                     = labels[i].parent ? cJSON_GetObjectItemCaseSensitive(json, labels[i].parent) : json;
        cJSON_ReplaceItemInObjectCaseSensitive(into, labels[i].field, cJSON_CreateString(value));
        api_request_t parsed = parseJson(json);
        require(! parsed.error, "Exact metadata length boundary was rejected");
        memoryFree(parsed.body);
        cJSON_Delete(json);

        json = requestJson("{}");
        into = labels[i].parent ? cJSON_GetObjectItemCaseSensitive(json, labels[i].parent) : json;
        cJSON_ReplaceItemInObjectCaseSensitive(into, labels[i].field, cJSON_CreateString(""));
        rejected(json, labels[i].error);
    }
    uint8_t bytes[32];
    require(apiserverTokenDecode(token, bytes), "Valid 32-byte token was rejected");
    require(bytes[0] == 0x01 && bytes[31] == 0xef, "Token hex decoding changed byte order");
    require(apiserverTokenDecode("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", bytes),
            "Uppercase hexadecimal token was rejected");
    require(! apiserverTokenDecode(NULL, bytes) && ! apiserverTokenDecode("", bytes) &&
                ! apiserverTokenDecode("ab", bytes),
            "Wrong-length token was accepted");
    cJSON *json = requestJson("{}");
    cJSON_ReplaceItemInObjectCaseSensitive(
        cJSON_GetObjectItemCaseSensitive(json, "auth"),
        "token",
        cJSON_CreateString("g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    rejected(json, "unauthorized");
}

static void lexicalAndEncoding(void)
{
    static const char *const nul_fields[] = {
        "id", "client", "token", "config", "node", "operation", "content_type", "body_encoding", "body"};
    for (size_t i = 0; i < sizeof(nul_fields) / sizeof(*nul_fields); ++i)
    {
        cJSON *json = requestJson("{}");
        char  *text = cJSON_PrintUnformatted(json);
        char   marker[64];
        snprintf(marker, sizeof(marker), "\"%s\":\"", nul_fields[i]);
        char  *start   = strstr(text, marker) + strlen(marker);
        size_t offset  = (size_t) (start - text);
        size_t length  = strlen(text);
        char  *corrupt = memoryAllocate(length + 7);
        memcpy(corrupt, text, offset);
        memcpy(corrupt + offset, "\\u0000", 6);
        memcpy(corrupt + offset + 6, text + offset, length - offset);
        rawRejected(corrupt, length + 6);
        memoryFree(corrupt);
        cJSON_free(text);
        cJSON_Delete(json);
    }
    static const char *const raw[] = {"{\"id\\u0000\":\"x\"}",
                                      "{\"id\":\"\xc0\xaf\"}",
                                      "{\"\xff\":1}",
                                      "{\"id\":\"\\ud800\"}",
                                      "[]",
                                      "null",
                                      "{}{}",
                                      "{\"id\":\"x\"} trailing"};
    for (size_t i = 0; i < sizeof(raw) / sizeof(*raw); ++i)
        rawRejected(raw[i], strlen(raw[i]));

    cJSON *json     = requestJson("{}");
    char  *text     = cJSON_PrintUnformatted(json);
    size_t n        = strlen(text);
    char  *trailing = memoryAllocate(n + 3);
    memcpy(trailing, text, n);
    memcpy(trailing + n, " {}", 3);
    rawRejected(trailing, n + 3);
    rawRejected(text, n - 1);
    memoryFree(trailing);
    cJSON_free(text);
    cJSON_Delete(json);

    static const char *const invalid_base64[] = {"Zg", "Zh==", "Zg=", "Zg===", " Zg==", "Zg==\n", "_w==", "Z=g="};
    for (size_t i = 0; i < sizeof(invalid_base64) / sizeof(*invalid_base64); ++i)
    {
        json = requestJson(invalid_base64[i]);
        cJSON_ReplaceItemInObjectCaseSensitive(json, "body_encoding", cJSON_CreateString("base64"));
        rejected(json, "invalid_encoding");
    }
    json = requestJson("{}");
    cJSON_ReplaceItemInObjectCaseSensitive(json, "body_encoding", cJSON_CreateString("UTF8"));
    rejected(json, "invalid_encoding");
}

static cJSON *encodedResponse(const char *id, const char *error, const node_api_operation_t *operation,
                              enum api_result_e code, const uint8_t *body, size_t length)
{
    size_t size = apiserverResponseSize(id, error, operation, code, body, length);
    require(size != SIZE_MAX && size < SIZE_MAX - 2, "Valid response size was refused");
    char *encoded = memoryAllocate(size + 2);
    memset(encoded, 0xa5, size + 2);
    apiserverResponseWrite(encoded, id, error, operation, code, body, length);
    require((uint8_t) encoded[size] == 0xa5 && (uint8_t) encoded[size + 1] == 0xa5,
            "Response writer exceeded its exact measured allocation");
    encoded[size] = '\0';
    require(strlen(encoded) == size, "Response writer underfilled or inserted an unescaped NUL");
    cJSON *json = cJSON_Parse(encoded);
    require(json != NULL, "Response writer generated invalid JSON");
    memoryFree(encoded);
    return json;
}

static void responseFidelity(void)
{
    static const uint8_t text[] = "\"\\\n\t\x01\xc3\xa9 {\"n\":18446744073709551615}";
    cJSON *json = encodedResponse("id-\"\\", NULL, &text_operation, kApiResultError, text, sizeof(text) - 1);
    require(strcmp(cJSON_GetObjectItemCaseSensitive(json, "id")->valuestring, "id-\"\\") == 0,
            "Response ID escaping changed bytes");
    require(cJSON_IsNull(cJSON_GetObjectItemCaseSensitive(json, "error")), "Node-level failure became a gateway error");
    cJSON *result = cJSON_GetObjectItemCaseSensitive(json, "result");
    require(cJSON_GetObjectItemCaseSensitive(result, "code")->valueint == kApiResultError, "Node failure code changed");
    require(strcmp(cJSON_GetObjectItemCaseSensitive(result, "body")->valuestring, (const char *) text) == 0,
            "Response escaping changed opaque text bytes");
    cJSON_Delete(json);

    static const uint8_t binary[] = {0, 0x7f, 0x80, 0xff};
    json   = encodedResponse("binary", NULL, &binary_operation, kApiResultOk, binary, sizeof(binary));
    result = cJSON_GetObjectItemCaseSensitive(json, "result");
    require(strcmp(cJSON_GetObjectItemCaseSensitive(result, "body")->valuestring, "AH+A/w==") == 0,
            "Response lost exact binary/base64 bytes");
    require(strcmp(cJSON_GetObjectItemCaseSensitive(result, "body_encoding")->valuestring, "base64") == 0,
            "Declared binary response encoding was ignored");
    cJSON_Delete(json);

    json   = encodedResponse("empty", NULL, &text_operation, kApiResultOk, NULL, 0);
    result = cJSON_GetObjectItemCaseSensitive(json, "result");
    require(cJSON_GetObjectItemCaseSensitive(result, "body")->valuestring[0] == '\0', "Null result was not empty");
    cJSON_Delete(json);
    uint8_t invalid_utf8[] = {0xc0, 0xaf};
    require(apiserverResponseSize("bad", NULL, &text_operation, kApiResultOk, invalid_utf8, sizeof(invalid_utf8)) ==
                SIZE_MAX,
            "Invalid UTF-8 result was emitted as text");
    require(apiserverResponseSize("overflow", NULL, &binary_operation, kApiResultOk, NULL, SIZE_MAX) == SIZE_MAX,
            "Overflowing base64 geometry was accepted");

    size_t   length = 70001;
    uint8_t *large  = memoryAllocate(length + 1);
    memset(large, 'q', length);
    large[length] = '\0';
    require(apiserverResponseSize("large", NULL, &text_operation, kApiResultOk, large, length) > 65535,
            "Large result length was truncated to 16 bits");
    json   = encodedResponse("large", NULL, &text_operation, kApiResultOk, large, length);
    result = cJSON_GetObjectItemCaseSensitive(json, "result");
    require(strlen(cJSON_GetObjectItemCaseSensitive(result, "body")->valuestring) == length,
            "Large response body was truncated");
    cJSON_Delete(json);
    json   = encodedResponse("large-binary", NULL, &binary_operation, kApiResultOk, large, length);
    result = cJSON_GetObjectItemCaseSensitive(json, "result");
    require(strlen(cJSON_GetObjectItemCaseSensitive(result, "body")->valuestring) == ((length + 2) / 3) * 4,
            "Large base64 expansion was mismeasured");
    cJSON_Delete(json);
    memset(large, 1, length);
    require(apiserverResponseSize("escaped", NULL, &text_operation, kApiResultOk, large, length) >= length * 6,
            "JSON control-byte expansion was not included in response size");
    memoryFree(large);
}

static void gatewayErrors(void)
{
    static const char *const errors[] = {"invalid_request",
                                         "invalid_encoding",
                                         "unauthorized",
                                         "forbidden",
                                         "target_not_found",
                                         "ambiguous_target",
                                         "unsupported_api",
                                         "unsupported_operation",
                                         "unsupported_content_type",
                                         "busy",
                                         "timeout",
                                         "shutting_down",
                                         "response_too_large"};
    for (size_t i = 0; i < sizeof(errors) / sizeof(*errors); ++i)
    {
        cJSON *json = encodedResponse(i ? "request" : NULL, errors[i], NULL, kApiResultError, NULL, 0);
        require(cJSON_IsNull(cJSON_GetObjectItemCaseSensitive(json, "result")), "Gateway failure had a node result");
        if (i == 0)
            require(cJSON_IsNull(cJSON_GetObjectItemCaseSensitive(json, "id")), "Untrusted request ID was echoed");
        cJSON *error = cJSON_GetObjectItemCaseSensitive(json, "error");
        require(strcmp(cJSON_GetObjectItemCaseSensitive(error, "code")->valuestring, errors[i]) == 0,
                "Gateway error code changed");
        require(strlen(cJSON_GetObjectItemCaseSensitive(error, "message")->valuestring) <= 128,
                "Gateway error diagnostic was unbounded");
        cJSON_Delete(json);
    }
}

int main(void)
{
    testCaseSet("apiserver_codec_test");
    validBodies();
    invalidSchema();
    labelsAndTokens();
    lexicalAndEncoding();
    responseFidelity();
    gatewayErrors();
    puts("apiserver_codec_test: all cases passed");
    return 0;
}
