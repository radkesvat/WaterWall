#include "modules/update_user/update_user.h"
#include "AuthenticationServer/audit.h"

#include "loggers/network_logger.h"

static const char *authenticationserverUsersUpdateResultError(users_update_result_t result)
{
    switch (result)
    {
    case kUsersUpdateResultOk:
        return "ok";
    case kUsersUpdateResultInvalidArgument:
    case kUsersUpdateResultUnknownFields:
    case kUsersUpdateResultInvalidRecordStatInterval:
        return "invalid-update-user-request";
    case kUsersUpdateResultInvalidWireGuardAllowedIps:
        return "invalid-wireguard-allowed-ips";
    case kUsersUpdateResultCapacityRejected:
        return "capacity-rejected";
    case kUsersUpdateResultUserNotFound:
        return "user-not-found";
    case kUsersUpdateResultDuplicateName:
        return "user-name-exists";
    case kUsersUpdateResultDuplicateUUID:
        return "user-uuid-exists";
    case kUsersUpdateResultDuplicateWireGuardPublicKey:
        return "user-wireguard-publickey-exists";
    case kUsersUpdateResultDuplicateWireGuardAllowedIps:
        return "user-wireguard-allowed-ips-overlap";
    case kUsersUpdateResultPasswordUpdateFailed:
        return "password-update-disabled";
    case kUsersUpdateResultRevisionExhausted:
        return "revision-exhausted";
    case kUsersUpdateResultTooLarge:
        return "user-too-large";
    case kUsersUpdateResultBusy:
    case kUsersUpdateResultResourceLimit:
    case kUsersUpdateResultTimeout:
    case kUsersUpdateResultPrecommitRejected:
        return "user-update-failed";
    }

    return "user-update-failed";
}

/* These objects are shallow, operation-specific configuration patches. The
 * lexical parser validates the complete byte span, UTF-8 and decoded keys. */
static bool readUnsigned(const cJSON *value, uint64_t *output, user_config_patch_t *patch, uint32_t bit)
{
    if (! getUint64FromJson(output, value))
        return false;
    patch->mask |= bit;
    return true;
}

static bool parseTrafficLimit(const cJSON *object, user_config_patch_t *patch, bool bandwidth)
{
    if (! cJSON_IsObject(object) || object->child == NULL)
        return false;
    const cJSON *field;
    cJSON_ArrayForEach(field, object)
    {
        if (stringCompare(field->string, "up") == 0)
        {
            if (! readUnsigned(field,
                               bandwidth ? &patch->limit.bandwidth.u : &patch->limit.traffic.u,
                               patch,
                               bandwidth ? kUserConfigBandwidthUp : kUserConfigTrafficUp))
                return false;
        }
        else if (stringCompare(field->string, "down") == 0)
        {
            if (! readUnsigned(field,
                               bandwidth ? &patch->limit.bandwidth.d : &patch->limit.traffic.d,
                               patch,
                               bandwidth ? kUserConfigBandwidthDown : kUserConfigTrafficDown))
                return false;
        }
        else if (! bandwidth && stringCompare(field->string, "total") == 0)
        {
            if (! readUnsigned(field, &patch->limit.traffic.total, patch, kUserConfigTrafficTotal))
                return false;
        }
        else
            return false;
    }
    return true;
}

static bool parseLimits(const cJSON *object, user_config_patch_t *patch)
{
    if (! cJSON_IsObject(object) || object->child == NULL)
        return false;
    const cJSON *field;
    cJSON_ArrayForEach(field, object)
    {
        if (stringCompare(field->string, "traffic") == 0 || stringCompare(field->string, "bandwidth") == 0)
        {
            if (! parseTrafficLimit(field, patch, stringCompare(field->string, "bandwidth") == 0))
                return false;
        }
        else if (stringCompare(field->string, "ips") == 0)
        {
            if (! readUnsigned(field, &patch->limit.ips, patch, kUserConfigIps))
                return false;
        }
        else if (stringCompare(field->string, "devices") == 0)
        {
            if (! readUnsigned(field, &patch->limit.devices, patch, kUserConfigDevices))
                return false;
        }
        else if (stringCompare(field->string, "connections-in") == 0)
        {
            if (! readUnsigned(field, &patch->limit.cons_in, patch, kUserConfigConnectionsIn))
                return false;
        }
        else if (stringCompare(field->string, "connections-out") == 0)
        {
            if (! readUnsigned(field, &patch->limit.cons_out, patch, kUserConfigConnectionsOut))
                return false;
        }
        else
            return false;
    }
    return true;
}

static bool parseTime(const cJSON *object, user_config_patch_t *patch)
{
    if (! cJSON_IsObject(object) || object->child == NULL)
        return false;
    const cJSON *field;
    cJSON_ArrayForEach(field, object)
    {
        if (stringCompare(field->string, "expire-at-ms") == 0)
        {
            if (! readUnsigned(field, &patch->expire_at_ms, patch, kUserConfigExpireAt))
                return false;
        }
        else if (stringCompare(field->string, "expire-after-first-usage-ms") == 0)
        {
            if (! readUnsigned(field, &patch->expire_after_first_usage_ms, patch, kUserConfigExpireAfterFirstUsage))
                return false;
        }
        else
            return false;
    }
    return true;
}

static bool parsePatch(const cJSON *object, user_config_patch_t *patch, uint64_t *id)
{
    if (! cJSON_IsObject(object))
        return false;
    const cJSON *field;
    cJSON_ArrayForEach(field, object)
    {
        if (stringCompare(field->string, "id") == 0)
        {
            if (! getUint64FromJson(id, field) || *id == 0)
                return false;
        }
        else if (stringCompare(field->string, "name") == 0 || stringCompare(field->string, "email") == 0 ||
                 stringCompare(field->string, "notes") == 0 ||
                 stringCompare(field->string, "wireguard-allowed-ips") == 0)
        {
            if (! cJSON_IsString(field))
                return false;
            if (stringCompare(field->string, "name") == 0)
            {
                patch->name = field->valuestring;
                patch->mask |= kUserConfigName;
            }
            else if (stringCompare(field->string, "email") == 0)
            {
                patch->email = field->valuestring;
                patch->mask |= kUserConfigEmail;
            }
            else if (stringCompare(field->string, "notes") == 0)
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
        else if (stringCompare(field->string, "gid") == 0)
        {
            if (! readUnsigned(field, &patch->gid, patch, kUserConfigGid))
                return false;
        }
        else if (stringCompare(field->string, "enabled") == 0)
        {
            if (! cJSON_IsBool(field))
                return false;
            patch->enabled = cJSON_IsTrue(field);
            patch->mask |= kUserConfigEnabled;
        }
        else if (stringCompare(field->string, "record-stat-interval-ms") == 0)
        {
            uint64_t interval;
            if (! getUint64FromJson(&interval, field) || interval > INT_MAX)
                return false;
            patch->record_stat_interval_ms = (int) interval;
            patch->mask |= kUserConfigRecordStatInterval;
        }
        else if (stringCompare(field->string, "limit") == 0)
        {
            if (! parseLimits(field, patch))
                return false;
        }
        else if (stringCompare(field->string, "time") == 0)
        {
            if (! parseTime(field, patch))
                return false;
        }
        else
            return false;
    }
    return *id != 0 && patch->mask != 0;
}

sbuf_t *authenticationserverUpdateUserHandle(const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
                                             tunnel_t *t, line_t *l, authenticationserver_session_t *session,
                                             const uint8_t *request_data, uint32_t request_data_len)
{
    authenticationserver_tstate_t *ts    = tunnelGetState(t);
    cJSON                         *json  = configLexicalParseQuiet((const char *) request_data, request_data_len, 8);
    user_config_patch_t            patch = {0};
    uint64_t                       id    = 0;
    if (json == NULL || ! parsePatch(json, &patch, &id))
    {
        cJSON_Delete(json);
        authenticationserverAuditRecordProducer(ts->audit,
                                                session != NULL ? session->client_name : NULL,
                                                "UpdateUser",
                                                id,
                                                0,
                                                patch.mask,
                                                "invalid-update-user-request");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-update-user-request");
    }
    const users_update_result_t result = authenticationserverPatchConfigAndBumpRevision(t, id, &patch);
    cJSON_Delete(json); /* The collection has already copied every selected string. */
    if (result != kUsersUpdateResultOk)
    {
        const char *error = authenticationserverUsersUpdateResultError(result);
        authenticationserverAuditRecordProducer(
            ts->audit, session != NULL ? session->client_name : NULL, "UpdateUser", id, 0, patch.mask, error);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, error);
    }
    authenticationserverAuditRecordProducer(ts->audit,
                                            session != NULL ? session->client_name : NULL,
                                            "UpdateUser",
                                            id,
                                            ts->store.config_revision,
                                            patch.mask,
                                            NULL);
    static const char ok[] = "user-updated";
    return authenticationserverCreateResponseFrame(
        l, kAuthenticationServerResponseTypeOk, correlation_id, (const uint8_t *) ok, (uint32_t) (sizeof(ok) - 1U));
}
