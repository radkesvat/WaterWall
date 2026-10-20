#include "AuthenticationServer/config_create.h"
#include "AuthenticationServer/config_fields.h"
#include "node_builder/config_lexical.h"

const char *authenticationserverParseCreate(sbuf_t *message, const node_api_call_context_t *context,
                                            authenticationserver_create_request_t *request)
{
    assert(message != NULL && context != NULL && request != NULL && ! sbufIsSplice(message));
    *request            = (authenticationserver_create_request_t) {0};
    const size_t length = sbufGetLength(message);
    /* Covers bounded nodes, decoded strings, duplicate-key sorting and parser
     * scratch. The dispatcher accounts for detached/request-buffer storage. */
    const size_t parser_charge =
        length <= kAuthenticationServerCreateRequestCap ? 2 * length + 64 * (sizeof(cJSON) + sizeof(char *) + 2) : 0;
    const char *error = NULL;
    cJSON      *body  = NULL;
    if (authenticationserverApiExpired(context->deadline_ms))
        error = "timeout";
    else if (length > kAuthenticationServerCreateRequestCap)
        error = "invalid_request";
    else if (context->working_memory_allowance < kAuthenticationServerApiScratchCharge + parser_charge)
        error = "resource_limit";
    else
        body = configLexicalParseBoundedQuiet((const char *) sbufGetRawPtr(message), length, 4, 64);
    if (error == NULL && ! cJSON_IsObject(body))
        error = "invalid_request";

    bool                has_id = false, has_password = false;
    const char         *password = NULL;
    user_config_patch_t config   = {0};
    for (const cJSON *field = body != NULL ? body->child : NULL; error == NULL && field != NULL; field = field->next)
    {
        if (strcmp(field->string, "id") == 0)
        {
            if (! authenticationserverConfigUnsignedString(field, &request->id) || request->id == 0)
                error = "invalid_request";
            has_id = true;
        }
        else if (strcmp(field->string, "password") == 0)
        {
            if (! cJSON_IsString(field) || field->valuestring[0] == '\0')
                error = "invalid_request";
            else
                password = field->valuestring;
            has_password = true;
        }
        else if (strcmp(field->string, "config") == 0)
        {
            if (! authenticationserverParseConfigFields(field, &config, true))
                error = "invalid_request";
        }
        else
            error = "invalid_request";
    }
    if (error == NULL && (! has_id || ! has_password))
        error = "invalid_request";
    if (error == NULL && authenticationserverApiExpired(context->deadline_ms))
        error = "timeout";
    if (error == NULL)
    {
        const size_t allowance =
            context->working_memory_allowance - kAuthenticationServerApiScratchCharge - parser_charge;
        error = authenticationserverConfigCreateError(
            usersPrepareNewUser(request->id, password, &config, allowance, context->deadline_ms, &request->candidate));
    }
    authenticationserverWipeJsonStrings(body);
    cJSON_Delete(body);
    memorySecureZero(sbufGetMutablePtr(message), length);
    bufferpoolReuseBuffer(getCurrentEventWorkerBufferPool(), message);
    if (authenticationserverApiExpired(context->deadline_ms))
        error = "timeout";
    if (error != NULL)
    {
        usersFreePreparedNewUser(request->candidate);
        request->candidate = NULL;
    }
    return error;
}
