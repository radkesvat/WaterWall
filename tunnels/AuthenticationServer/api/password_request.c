#include "AuthenticationServer/config_fields.h"
#include "AuthenticationServer/password_change.h"
#include "node_builder/config_lexical.h"

const char *authenticationserverParsePasswordChange(sbuf_t *message, const node_api_call_context_t *context,
                                                    authenticationserver_password_request_t *request)
{
    assert(message != NULL && context != NULL && request != NULL && ! sbufIsSplice(message));
    *request            = (authenticationserver_password_request_t) {0};
    const size_t length = sbufGetLength(message);
    /* Nodes, decoded strings, duplicate-key sorting and lexical scratch overlap
     * preparation. Detached/request-buffer storage is charged by dispatch. */
    const size_t parser_charge =
        length <= kAuthenticationServerPasswordRequestCap ? 2 * length + 16 * (sizeof(cJSON) + sizeof(char *) + 2) : 0;
    const char *error = NULL;
    cJSON      *body  = NULL;
    if (authenticationserverApiExpired(context->deadline_ms))
        error = "timeout";
    else if (length > kAuthenticationServerPasswordRequestCap)
        error = "invalid_request";
    else if (context->working_memory_allowance < kAuthenticationServerApiScratchCharge + parser_charge)
        error = "resource_limit";
    else
        body = configLexicalParseBoundedQuiet((const char *) sbufGetRawPtr(message), length, 1, 16);
    if (error == NULL && ! cJSON_IsObject(body))
        error = "invalid_request";

    bool        has_id = false, has_match = false, has_password = false;
    const char *password = NULL;
    for (const cJSON *field = body != NULL ? body->child : NULL; error == NULL && field != NULL; field = field->next)
    {
        if (strcmp(field->string, "id") == 0)
        {
            if (! authenticationserverConfigUnsignedString(field, &request->id) || request->id == 0)
                error = "invalid_request";
            has_id = true;
        }
        else if (strcmp(field->string, "if_match") == 0)
        {
            if (! cJSON_IsString(field) ||
                ! authenticationserverEditTokenParse(field->valuestring, request->instance_id, &request->revision))
                error = "invalid_request";
            has_match = true;
        }
        else if (strcmp(field->string, "password") == 0)
        {
            if (! cJSON_IsString(field) || field->valuestring[0] == '\0')
                error = "invalid_request";
            else
                password = field->valuestring;
            has_password = true;
        }
        else
            error = "invalid_request";
    }
    if (error == NULL && (! has_id || ! has_match || ! has_password))
        error = "invalid_request";
    if (error == NULL && authenticationserverApiExpired(context->deadline_ms))
        error = "timeout";
    if (error == NULL)
    {
        const size_t allowance =
            context->working_memory_allowance - kAuthenticationServerApiScratchCharge - parser_charge;
        error = authenticationserverPasswordChangeError(
            usersPreparePasswordChange(password, allowance, context->deadline_ms, &request->password));
    }
    authenticationserverWipeJsonStrings(body);
    cJSON_Delete(body);
    memorySecureZero(sbufGetMutablePtr(message), length);
    bufferpoolReuseBuffer(getCurrentWorkerBufferPool(), message);
    if (authenticationserverApiExpired(context->deadline_ms))
        error = "timeout";
    if (error != NULL)
    {
        usersFreePreparedPasswordChange(request->password);
        request->password = NULL;
    }
    return error;
}
