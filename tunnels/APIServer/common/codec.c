#include "APIServer/codec.h"

bool apiserverObjectKeysValid(const cJSON *object, const char *const *allowed, size_t count)
{
    if (! cJSON_IsObject(object))
        return false;
    for (const cJSON *item = object->child; item; item = item->next)
    {
        size_t i = 0;
        for (; i < count; ++i)
            if (strcmp(item->string, allowed[i]) == 0)
                break;
        if (i == count)
            return false;
        for (const cJSON *prior = object->child; prior != item; prior = prior->next)
            if (strcmp(prior->string, item->string) == 0)
                return false;
    }
    return true;
}

static bool stringField(const cJSON *object, const char *key, char *dest, size_t capacity)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, key);
    if (! cJSON_IsString(item) || item->valuestring[0] == '\0' || strlen(item->valuestring) >= capacity)
        return false;
    strcpy(dest, item->valuestring);
    return true;
}

static int hexDigit(unsigned char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

bool apiserverTokenDecode(const char *text, uint8_t bytes[32])
{
    if (! text || strlen(text) != 64)
        return false;
    for (size_t i = 0; i < 32; ++i)
    {
        int high = hexDigit((unsigned char) text[i * 2]);
        int low  = hexDigit((unsigned char) text[i * 2 + 1]);
        if (high < 0 || low < 0)
            return false;
        bytes[i] = (uint8_t) ((high << 4) | low);
    }
    return true;
}

void apiserverRequestParse(api_request_t *r, const char *bytes, size_t length)
{
    static const char *const outer[] = {"id", "auth", "selector", "operation", "content_type", "body_encoding", "body"};
    static const char *const selector_keys[] = {"config", "node"};
    static const char *const auth_keys[]     = {"client", "token"};
    r->error                                 = "invalid_request";
    r->close                                 = true;
    cJSON *json = configLexicalParseBoundedQuietWithCleanup(bytes, length, 3, 40, jsonWipeStrings);
    if (! json)
        return;
    if (! cJSON_IsObject(json))
        goto done;
    if (! stringField(json, "id", r->id, sizeof(r->id)))
        goto done;
    if (! apiserverObjectKeysValid(json, outer, ARRAY_SIZE(outer)))
        goto done;
    const cJSON *selector = cJSON_GetObjectItemCaseSensitive(json, "selector");
    const cJSON *config   = cJSON_GetObjectItemCaseSensitive(selector, "config");
    if (! apiserverObjectKeysValid(selector, selector_keys, ARRAY_SIZE(selector_keys)) ||
        ! stringField(selector, "node", r->node, sizeof(r->node)) ||
        (config && ! stringField(selector, "config", r->config, sizeof(r->config))) ||
        ! stringField(json, "operation", r->operation, sizeof(r->operation)) ||
        ! stringField(json, "content_type", r->content_type, sizeof(r->content_type)))
        goto done;
    const cJSON *auth = cJSON_GetObjectItemCaseSensitive(json, "auth");
    if (cJSON_IsObject(auth) && ! apiserverObjectKeysValid(auth, auth_keys, ARRAY_SIZE(auth_keys)))
        goto done;
    const cJSON *token = cJSON_GetObjectItemCaseSensitive(auth, "token");
    if (! stringField(auth, "client", r->client, sizeof(r->client)) || ! cJSON_IsString(token) ||
        ! apiserverTokenDecode(token->valuestring, r->token))
    {
        r->error = "unauthorized";
        goto done;
    }
    const cJSON *encoding = cJSON_GetObjectItemCaseSensitive(json, "body_encoding");
    const cJSON *body     = cJSON_GetObjectItemCaseSensitive(json, "body");
    if (! cJSON_IsString(body) || ! cJSON_IsString(encoding))
        goto done;
    size_t n         = strlen(body->valuestring);
    r->body_capacity = n + 1;
    r->body          = memoryAllocate(r->body_capacity);
    if (strcmp(encoding->valuestring, "utf8") == 0)
    {
        memcpy(r->body, body->valuestring, n);
        r->body_size = n;
    }
    else if (strcmp(encoding->valuestring, "base64") == 0 && n <= UINT_MAX)
    {
        int decoded = wwBase64DecodeCanonical(body->valuestring, (unsigned int) n, r->body, n);
        if (decoded < 0)
        {
            r->error = "invalid_encoding";
            goto done;
        }
        r->body_size = (size_t) decoded;
    }
    else
    {
        r->error = "invalid_encoding";
        goto done;
    }
    r->error = NULL;
    r->close = false;
done:
    if (r->error != NULL)
        memorySecureZero(r->token, sizeof(r->token));
    jsonWipeStrings(json);
    cJSON_Delete(json);
}

void apiserverRequestClear(api_request_t *request)
{
    assert(request != NULL);
    if (request->body != NULL)
    {
        memorySecureZero(request->body, request->body_capacity);
        memoryFree(request->body);
    }
    memorySecureZero(request->token, sizeof(request->token));
    *request = (api_request_t) {0};
}

static const char *errorMessage(const char *code)
{
    if (strcmp(code, "ambiguous_target") == 0)
        return "Specify the configuration name.";
    if (strcmp(code, "unauthorized") == 0)
        return "Invalid API credentials.";
    if (strcmp(code, "forbidden") == 0)
        return "Operation is not permitted.";
    if (strcmp(code, "target_not_found") == 0)
        return "Target was not found.";
    if (strcmp(code, "unsupported_api") == 0)
        return "Target has no registered API.";
    if (strcmp(code, "unsupported_operation") == 0)
        return "Operation is not registered.";
    if (strcmp(code, "unsupported_content_type") == 0)
        return "Content type is not supported.";
    if (strcmp(code, "busy") == 0)
        return "API capacity is exhausted.";
    if (strcmp(code, "timeout") == 0)
        return "API deadline expired.";
    if (strcmp(code, "shutting_down") == 0)
        return "API admission is closed.";
    if (strcmp(code, "invalid_response") == 0)
        return "The handler returned an invalid response.";
    if (strcmp(code, "response_too_large") == 0)
        return "Response exceeds the configured limit.";
    if (strcmp(code, "invalid_encoding") == 0)
        return "Invalid body encoding.";
    return "Invalid API request.";
}

/* The same writer measures and emits; all additions saturate before allocation. */
typedef struct writer_s
{
    char  *out;
    size_t size;
    bool   invalid;
} writer_t;

static void append(writer_t *w, const void *bytes, size_t n)
{
    if (w->size == SIZE_MAX || n > SIZE_MAX - w->size)
    {
        w->size = SIZE_MAX;
        return;
    }
    if (w->out && bytes != w->out + w->size)
        memcpy(w->out + w->size, bytes, n);
    w->size += n;
}

static void literal(writer_t *w, const char *text)
{
    append(w, text, strlen(text));
}

static void quoted(writer_t *w, const uint8_t *bytes, size_t n)
{
    static const char hex[] = "0123456789abcdef";
    literal(w, "\"");
    for (size_t i = 0; i < n; ++i)
    {
        unsigned char c = bytes[i];
        if (c == '"' || c == '\\')
        {
            char escape[] = {'\\', (char) c};
            append(w, escape, 2);
        }
        else if (c < 0x20)
        {
            char escape[] = {'\\', 'u', '0', '0', hex[c >> 4], hex[c & 15]};
            append(w, escape, 6);
        }
        else
            append(w, &c, 1);
    }
    literal(w, "\"");
}

static void textString(writer_t *w, const char *text)
{
    quoted(w, (const uint8_t *) text, strlen(text));
}

static void response(writer_t *w, const char *id, const char *error, const node_api_operation_t *op,
                     enum api_result_e code, const uint8_t *body, size_t length)
{
    literal(w, "{\"id\":");
    if (id && *id)
        textString(w, id);
    else
        literal(w, "null");
    if (error)
    {
        literal(w, ",\"error\":{\"code\":");
        textString(w, error);
        literal(w, ",\"message\":");
        textString(w, errorMessage(error));
        literal(w, "},\"result\":null}");
        return;
    }
    assert(op != NULL);
    char number[32];
    snprintf(number, sizeof(number), "%d", (int) code);
    literal(w, ",\"error\":null,\"result\":{\"code\":");
    literal(w, number);
    literal(w, ",\"content_type\":");
    textString(w, op->response_content_type);
    literal(w, ",\"body_encoding\":");
    textString(w, op->response_encoding == kNodeApiEncodingBase64 ? "base64" : "utf8");
    literal(w, ",\"body\":");
    if (op->response_encoding == kNodeApiEncodingBase64)
    {
        if (length > (SIZE_MAX - 2) / 4 * 3 || length > UINT_MAX)
        {
            w->size = SIZE_MAX;
            return;
        }
        size_t encoded = ((length + 2) / 3) * 4;
        literal(w, "\"");
        /* Encode directly into the final allocation, never allocate a second body. */
        if (w->out && w->size != SIZE_MAX)
            discard wwBase64Encode(body, (unsigned int) length, w->out + w->size);
        append(w, w->out ? w->out + w->size : NULL, encoded);
        literal(w, "\"");
    }
    else
    {
        if (! configLexicalCheckEncodingQuiet((const char *) body, length))
        {
            w->invalid = true;
            w->size    = SIZE_MAX;
            return;
        }
        quoted(w, body, length);
    }
    literal(w, "}}");
}

api_response_measure_t apiserverResponseMeasure(const char *id, const char *error, const node_api_operation_t *op,
                                                enum api_result_e code, const uint8_t *body, size_t length,
                                                size_t *encoded_size)
{
    writer_t w = {0};
    response(&w, id, error, op, code, body, length);
    *encoded_size = w.size;
    return w.invalid ? kApiResponseInvalid : w.size == SIZE_MAX ? kApiResponseTooLarge : kApiResponseValid;
}

size_t apiserverResponseSize(const char *id, const char *error, const node_api_operation_t *op, enum api_result_e code,
                             const uint8_t *body, size_t length)
{
    size_t  size;
    discard apiserverResponseMeasure(id, error, op, code, body, length, &size);
    return size;
}

void apiserverResponseWrite(char *dest, const char *id, const char *error, const node_api_operation_t *op,
                            enum api_result_e code, const uint8_t *body, size_t length)
{
    writer_t w = {.out = dest};
    response(&w, id, error, op, code, body, length);
}
