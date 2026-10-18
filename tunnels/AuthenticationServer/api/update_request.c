#include "AuthenticationServer/config_update.h"
#include "node_builder/config_lexical.h"

static bool unsignedString(const cJSON *value, uint64_t *out)
{
    if (! cJSON_IsString(value) || value->valuestring[0] < '0' || value->valuestring[0] > '9')
        return false;
    const char *text = value->valuestring;
    if (text[0] == '0' && text[1] != '\0')
        return false;
    uint64_t number = 0;
    for (size_t i = 0; text[i] != '\0'; ++i)
    {
        if (i >= 20 || text[i] < '0' || text[i] > '9')
            return false;
        unsigned digit = (unsigned) (text[i] - '0');
        if (number > (UINT64_MAX - digit) / 10)
            return false;
        number = number * 10 + digit;
    }
    *out = number;
    return true;
}

static bool unsignedLeaf(const cJSON *value, uint64_t *out, user_config_patch_t *patch, uint32_t bit)
{
    if (! unsignedString(value, out))
        return false;
    patch->mask |= bit;
    return true;
}

static bool traffic(const cJSON *object, user_config_patch_t *patch, bool bandwidth)
{
    if (! cJSON_IsObject(object) || object->child == NULL)
        return false;
    const cJSON *field;
    cJSON_ArrayForEach(field, object)
    {
        if (strcmp(field->string, "u") == 0)
        {
            if (! unsignedLeaf(field,
                               bandwidth ? &patch->limit.bandwidth.u : &patch->limit.traffic.u,
                               patch,
                               bandwidth ? kUserConfigBandwidthUp : kUserConfigTrafficUp))
                return false;
        }
        else if (strcmp(field->string, "d") == 0)
        {
            if (! unsignedLeaf(field,
                               bandwidth ? &patch->limit.bandwidth.d : &patch->limit.traffic.d,
                               patch,
                               bandwidth ? kUserConfigBandwidthDown : kUserConfigTrafficDown))
                return false;
        }
        else if (! bandwidth && strcmp(field->string, "total") == 0)
        {
            if (! unsignedLeaf(field, &patch->limit.traffic.total, patch, kUserConfigTrafficTotal))
                return false;
        }
        else
            return false;
    }
    return true;
}

static bool limits(const cJSON *object, user_config_patch_t *patch)
{
    if (! cJSON_IsObject(object) || object->child == NULL)
        return false;
    const cJSON *field;
    cJSON_ArrayForEach(field, object)
    {
        if (strcmp(field->string, "traffic") == 0 || strcmp(field->string, "bandwidth") == 0)
        {
            if (! traffic(field, patch, strcmp(field->string, "bandwidth") == 0))
                return false;
        }
        else if (strcmp(field->string, "ips") == 0)
        {
            if (! unsignedLeaf(field, &patch->limit.ips, patch, kUserConfigIps))
                return false;
        }
        else if (strcmp(field->string, "devices") == 0)
        {
            if (! unsignedLeaf(field, &patch->limit.devices, patch, kUserConfigDevices))
                return false;
        }
        else if (strcmp(field->string, "cons_in") == 0)
        {
            if (! unsignedLeaf(field, &patch->limit.cons_in, patch, kUserConfigConnectionsIn))
                return false;
        }
        else if (strcmp(field->string, "cons_out") == 0)
        {
            if (! unsignedLeaf(field, &patch->limit.cons_out, patch, kUserConfigConnectionsOut))
                return false;
        }
        else
            return false;
    }
    return true;
}

static bool times(const cJSON *object, user_config_patch_t *patch)
{
    if (! cJSON_IsObject(object) || object->child == NULL)
        return false;
    const cJSON *field;
    cJSON_ArrayForEach(field, object)
    {
        if (strcmp(field->string, "expire_at_ms") == 0)
        {
            if (! unsignedLeaf(field, &patch->expire_at_ms, patch, kUserConfigExpireAt))
                return false;
        }
        else if (strcmp(field->string, "expire_after_first_usage_ms") == 0)
        {
            if (! unsignedLeaf(field, &patch->expire_after_first_usage_ms, patch, kUserConfigExpireAfterFirstUsage))
                return false;
        }
        else
            return false;
    }
    return true;
}

static bool parsePatch(const cJSON *object, user_config_patch_t *patch)
{
    if (! cJSON_IsObject(object) || object->child == NULL)
        return false;
    const cJSON *field;
    cJSON_ArrayForEach(field, object)
    {
        if (strcmp(field->string, "name") == 0 || strcmp(field->string, "email") == 0 ||
            strcmp(field->string, "notes") == 0 || strcmp(field->string, "wireguard_allowed_ips") == 0)
        {
            if (! cJSON_IsString(field))
                return false;
            if (strcmp(field->string, "name") == 0)
            {
                patch->name = field->valuestring;
                patch->mask |= kUserConfigName;
            }
            else if (strcmp(field->string, "email") == 0)
            {
                patch->email = field->valuestring;
                patch->mask |= kUserConfigEmail;
            }
            else if (strcmp(field->string, "notes") == 0)
            {
                patch->notes = field->valuestring;
                patch->mask |= kUserConfigNotes;
            }
            else
            {
                patch->wireguard_allowed_ips = field->valuestring;
                patch->mask |= kUserConfigWireGuardAllowedIps;
            }
        }
        else if (strcmp(field->string, "gid") == 0)
        {
            if (! unsignedLeaf(field, &patch->gid, patch, kUserConfigGid))
                return false;
        }
        else if (strcmp(field->string, "enabled") == 0)
        {
            if (! cJSON_IsBool(field))
                return false;
            patch->enabled = cJSON_IsTrue(field);
            patch->mask |= kUserConfigEnabled;
        }
        else if (strcmp(field->string, "record_stat_interval_ms") == 0)
        {
            uint64_t interval;
            if (! unsignedString(field, &interval) || interval > INT_MAX)
                return false;
            patch->record_stat_interval_ms = (int) interval;
            patch->mask |= kUserConfigRecordStatInterval;
        }
        else if (strcmp(field->string, "limit") == 0)
        {
            if (! limits(field, patch))
                return false;
        }
        else if (strcmp(field->string, "time") == 0)
        {
            if (! times(field, patch))
                return false;
        }
        else
            return false;
    }
    return patch->mask != 0;
}

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
            if (! unsignedString(field, &request->id) || request->id == 0)
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
            if (! parsePatch(field, &patch))
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
