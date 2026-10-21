#include "AuthenticationServer/api.h"

bool authenticationserverApiExpired(uint64_t deadline_ms)
{
    return deadline_ms != 0 && nodeApiNowMs() >= deadline_ms;
}

bool authenticationserverApiUnsignedDecimal(const char *text, uint64_t *value)
{
    if (text == NULL || text[0] < '0' || text[0] > '9')
        return false;
    if (text[0] == '0' && text[1] != '\0')
        return false;
    uint64_t result = 0;
    for (size_t i = 0; text[i] != '\0'; ++i)
    {
        if (i >= 20 || text[i] < '0' || text[i] > '9')
            return false;
        unsigned digit = (unsigned) (text[i] - '0');
        if (result > (UINT64_MAX - digit) / 10)
            return false;
        result = result * 10 + digit;
    }
    *value = result;
    return true;
}

/* Keep the integer lexeme requirement after the bounded parser has validated
 * JSON syntax. Numbers inside strings (including escaped keys) are skipped. */
static bool integerLexemes(const char *text, size_t length)
{
    for (size_t i = 0; i < length; ++i)
    {
        if (text[i] == '"')
        {
            while (++i < length && text[i] != '"')
                if (text[i] == '\\')
                    ++i;
        }
        else if (text[i] == '-' || (text[i] >= '0' && text[i] <= '9'))
        {
            while (i < length && text[i] != ',' && text[i] != '}' && ! isspace((unsigned char) text[i]))
            {
                if (text[i] < '0' || text[i] > '9')
                    return false;
                ++i;
            }
        }
    }
    return true;
}

bool authenticationserverApiCursorDecode(const char *text, authenticationserver_api_request_t *request)
{
    if (text == NULL || strlen(text) != 64)
        return false;
    uint8_t bytes[32];
    for (size_t i = 0; i < 64; ++i)
    {
        unsigned digit;
        if (text[i] >= '0' && text[i] <= '9')
            digit = (unsigned) (text[i] - '0');
        else if (text[i] >= 'a' && text[i] <= 'f')
            digit = (unsigned) (text[i] - 'a' + 10);
        else
            return false;
        if ((i & 1) == 0)
            bytes[i / 2] = (uint8_t) (digit << 4);
        else
            bytes[i / 2] |= (uint8_t) digit;
    }
    memoryCopy(request->instance_id, bytes, 16);
    for (size_t i = 16; i < 24; ++i)
        request->revision = (request->revision << 8) | bytes[i];
    for (size_t i = 24; i < 32; ++i)
        request->position = (request->position << 8) | bytes[i];
    request->has_cursor = true;
    return true;
}

const char *authenticationserverApiParse(sbuf_t *message, const node_api_call_context_t *context,
                                         authenticationserver_api_kind_t     kind,
                                         authenticationserver_api_request_t *request)
{
    assert(message != NULL && context != NULL && request != NULL && ! sbufIsSplice(message));
    *request           = (authenticationserver_api_request_t) {.limit = 50};
    size_t      length = sbufGetLength(message);
    const char *error  = NULL;
    cJSON      *body   = NULL;
    if (authenticationserverApiExpired(context->deadline_ms))
        error = "timeout";
    else if (length > kAuthenticationServerApiRequestCap)
        error = "invalid_request";
    else if (context->working_memory_allowance < kAuthenticationServerApiScratchCharge + length * 4)
        error = "response_too_large";
    else
    {
        const char *text = (const char *) sbufGetRawPtr(message);
        body             = configLexicalParseBoundedQuiet(text, length, 2, 16);
        if (! cJSON_IsObject(body) || ! integerLexemes(text, length))
            error = "invalid_request";
    }
    bool has_id = false;
    for (const cJSON *field = body != NULL ? body->child : NULL; error == NULL && field != NULL; field = field->next)
    {
        if (kind == kAuthenticationServerApiGetUser && strcmp(field->string, "id") == 0)
        {
            if (! cJSON_IsString(field) ||
                (! authenticationserverApiUnsignedDecimal(field->valuestring, &request->id) || request->id == 0))
                error = "invalid_request";
            has_id = true;
        }
        else if (kind == kAuthenticationServerApiListUsers && strcmp(field->string, "limit") == 0)
        {
            if (! cJSON_IsNumber(field) || field->valuedouble < 1 || field->valuedouble > 100 ||
                field->valuedouble != (double) field->valueint)
                error = "invalid_request";
            else
                request->limit = (size_t) field->valueint;
        }
        else if (kind == kAuthenticationServerApiListUsers && strcmp(field->string, "cursor") == 0)
        {
            if (! cJSON_IsString(field) || ! authenticationserverApiCursorDecode(field->valuestring, request))
                error = "invalid_cursor";
        }
        else
            error = "invalid_request";
    }
    if (error == NULL && kind == kAuthenticationServerApiGetUser && ! has_id)
        error = "invalid_request";
    cJSON_Delete(body);
    bufferpoolReuseBuffer(getCurrentWorkerBufferPool(), message);
    if (authenticationserverApiExpired(context->deadline_ms))
        error = "timeout";
    return error;
}

void authenticationserverWipeJsonStrings(cJSON *item)
{
    for (; item != NULL; item = item->next)
    {
        authenticationserverWipeJsonStrings(item->child);
        if (item->valuestring != NULL)
            memorySecureZero(item->valuestring, strlen(item->valuestring));
        if (item->string != NULL)
            memorySecureZero(item->string, strlen(item->string));
    }
}
