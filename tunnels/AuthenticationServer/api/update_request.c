#include "AuthenticationServer/config_fields.h"
#include "AuthenticationServer/config_update.h"
#include "node_builder/config_lexical.h"

const char *authenticationserverParseUpdate(sbuf_t *message, const node_api_call_context_t *context,
                                            authenticationserver_update_request_t *request)
{
    assert(message != NULL && context != NULL && request != NULL && ! sbufIsSplice(message));
    *request            = (authenticationserver_update_request_t) {0};
    const size_t length = sbufGetLength(message);
    /* The lexical limit counts keys as well as values. This conservative peak
     * includes nodes, decoded strings, duplicate-key sorting and parser scratch.
     * The dispatcher reserves request-buffer storage separately. */
    const size_t parser_charge =
        length <= kAuthenticationServerUpdateRequestCap ? 2 * length + 64 * (sizeof(cJSON) + sizeof(char *) + 2) : 0;
    const char *error = NULL;
    cJSON      *body  = NULL;
    if (authenticationserverApiExpired(context->deadline_ms))
        error = "timeout";
    else if (length > kAuthenticationServerUpdateRequestCap)
        error = "invalid_request";
    else if (context->working_memory_allowance < kAuthenticationServerApiScratchCharge + parser_charge)
        error = "resource_limit";
    else
        body = configLexicalParseBounded((const char *) sbufGetRawPtr(message), length, 4, 64);
    if (error == NULL && ! cJSON_IsObject(body))
        error = "invalid_request";

    bool                has_id = false, has_match = false, has_patch = false;
    user_config_patch_t patch = {0};
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
        else if (strcmp(field->string, "patch") == 0)
        {
            if (! authenticationserverParseConfigFields(field, &patch, false))
                error = "invalid_request";
            has_patch = true;
        }
        else
            error = "invalid_request";
    }
    if (error == NULL && (! has_id || ! has_match || ! has_patch))
        error = "invalid_request";
    if (error == NULL)
    {
        size_t allowance = context->working_memory_allowance - kAuthenticationServerApiScratchCharge - parser_charge;
        users_update_result_t result =
            usersPrepareConfigPatch(&patch, allowance, context->deadline_ms, &request->patch);
        error = authenticationserverConfigUpdateError(result);
    }
    request->audit_fields = patch.mask;
    cJSON_Delete(body);
    bufferpoolReuseBuffer(getCurrentEventWorkerBufferPool(), message);
    if (authenticationserverApiExpired(context->deadline_ms))
        error = "timeout";
    if (error != NULL)
    {
        usersFreePreparedConfigPatch(request->patch);
        request->patch = NULL;
    }
    return error;
}
