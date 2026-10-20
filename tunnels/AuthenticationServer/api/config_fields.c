#include "AuthenticationServer/config_fields.h"
#include "AuthenticationServer/api.h"

bool authenticationserverConfigUnsignedString(const cJSON *value, uint64_t *out)
{
    return cJSON_IsString(value) && authenticationserverApiUnsignedDecimal(value->valuestring, out);
}

static bool unsignedLeaf(const cJSON *value, uint64_t *out, user_config_patch_t *patch, uint32_t bit)
{
    if (! authenticationserverConfigUnsignedString(value, out))
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

bool authenticationserverParseConfigFields(const cJSON *object, user_config_patch_t *patch, bool allow_empty)
{
    if (! cJSON_IsObject(object) || (! allow_empty && object->child == NULL))
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
            if (! authenticationserverConfigUnsignedString(field, &interval) || interval > INT_MAX)
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
    return allow_empty || patch->mask != 0;
}
