#include "auth.h"
#include "internal.h"

#include "UserController/interface.h"

#include "loggers/network_logger.h"

enum
{
    kVmessServerDefaultFallbackIntentionalDelayMs       = 7,
    kVmessServerDefaultFallbackIntentionalDelayJitterMs = 1
};

static hash_t vmessserverAuthenticationClientTypeHash(void)
{
    const char *type_name = "AuthenticationClient";
    return calcHashBytes(type_name, stringLength(type_name));
}

static bool vmessserverParseAuthClientNode(vmessserver_tstate_t *ts, node_t *node, const char *auth_client_node_name)
{
    node_t *auth_client_node = nodemanagerGetConfigNodeByName(node->node_manager_config, auth_client_node_name);
    if (auth_client_node == NULL)
    {
        LOGF("VmessServer: auth-client-node-name \"%s\" was not found", auth_client_node_name);
        return false;
    }

    if (auth_client_node == node)
    {
        LOGF("VmessServer: auth-client-node-name must not point back to VmessServer itself");
        return false;
    }

    if (auth_client_node->hash_type != vmessserverAuthenticationClientTypeHash())
    {
        LOGF("VmessServer: auth-client-node-name \"%s\" must point to an AuthenticationClient node",
             auth_client_node_name);
        return false;
    }

    ts->auth_client_node = auth_client_node;
    return true;
}

static bool vmessserverParseFallbackNode(vmessserver_tstate_t *ts, node_t *node, const cJSON *settings)
{
    const cJSON *fallback_json = getJsonObjectItemByKeys(settings, "fallback-node-name", "fallback-node", "fallback");

    if (fallback_json == NULL)
    {
        ts->fallback_node = NULL;
        return true;
    }

    if (! cJSON_IsString(fallback_json) || fallback_json->valuestring == NULL || fallback_json->valuestring[0] == '\0')
    {
        LOGF("JSON Error: VmessServer->settings->fallback-node-name (string field) must be a non-empty string");
        return false;
    }

    node_t *fallback_node = nodemanagerGetConfigNodeByName(node->node_manager_config, fallback_json->valuestring);
    if (fallback_node == NULL)
    {
        LOGF("VmessServer: fallback node \"%s\" was not found", fallback_json->valuestring);
        return false;
    }

    if (fallback_node == node)
    {
        LOGF("VmessServer: fallback node must not point back to VmessServer itself");
        return false;
    }

    ts->fallback_node = fallback_node;
    return true;
}

static usercontroller_payload_mode_t vmessserverResolvePayloadMode(tunnel_t *owner, line_t *line)
{
    const vmessserver_lstate_t *ls = lineGetState(line, owner);
    return ls->line_kind == kVmessServerLineKindUdpRemote ? kUserControllerPayloadDatagram
                                                          : kUserControllerPayloadStream;
}

static bool vmessserverCreateUserControllerTunnel(tunnel_t *t, node_t *node)
{
    vmessserver_tstate_t *ts = tunnelGetState(t);

    if (! nodeConfigureChild(&ts->user_controller_node,
                             nodeUserControllerGet(),
                             node,
                             ".user-controller",
                             kNodeChildLinkOwnerNext,
                             node->node_settings_json))
    {
        LOGF("VmessServer: failed to configure internal UserController node");
        return false;
    }

    ts->user_controller_tunnel = nodemanagerCreateTunnelInstance(&ts->user_controller_node);
    if (ts->user_controller_tunnel == NULL)
    {
        LOGF("VmessServer: failed to create internal UserController");
        return false;
    }

    usercontrollerSetPayloadModeResolver(ts->user_controller_tunnel, t, vmessserverResolvePayloadMode);
    ts->user_controller_node.instance = ts->user_controller_tunnel;
    return true;
}

static bool vmessserverAppendUuid(vmessserver_tstate_t *ts, const uint8_t uuid[kVmessServerUuidLen],
                                  const char *username, const char *path)
{
    for (uint32_t i = 0; i < ts->user_count; ++i)
    {
        if (memoryEqual(ts->users[i].uuid, uuid, kVmessServerUuidLen))
        {
            LOGF("JSON Error: VmessServer->settings->%s duplicates a configured local UUID", path);
            return false;
        }
    }

    size_t new_count = (size_t) ts->user_count + 1U;
    if (UNLIKELY(ts->user_count == UINT32_MAX || new_count > SIZE_MAX / sizeof(*ts->users)))
    {
        LOGF("VmessServer: too many configured users");
        return false;
    }

    vmessserver_user_t *users = memoryReAllocate(ts->users, sizeof(*users) * new_count);

    ts->users       = users;
    char *name_copy = username != NULL ? stringDuplicate(username) : NULL;
    memoryCopy(ts->users[ts->user_count].uuid, uuid, kVmessServerUuidLen);
    ts->users[ts->user_count].username = name_copy;
    ts->user_count                     = (uint32_t) new_count;
    return true;
}

static bool vmessserverParseUuidValue(vmessserver_tstate_t *ts, const cJSON *item, const char *path,
                                      const char *username)
{
    if (! cJSON_IsString(item) || item->valuestring == NULL || item->valuestring[0] == '\0' ||
        (item->type & cJSON_StringHasEmbeddedNul) != 0)
    {
        LOGF("JSON Error: VmessServer->settings->%s must be a non-empty UUID string", path);
        return false;
    }

    uint8_t uuid[kVmessServerUuidLen] = {0};
    if (vmessNormalizeId(item->valuestring, strlen(item->valuestring), uuid) != kWCryptoOk)
    {
        LOGF("JSON Error: VmessServer->settings->%s must be a UUID or a UTF-8 ID of 1..30 bytes", path);
        return false;
    }

    return vmessserverAppendUuid(ts, uuid, username, path);
}

static const cJSON *vmessserverGetObjectUuidField(const cJSON *item, const char *path, bool *invalid)
{
    *invalid                 = false;
    const char *const keys[] = {"uuid", "id", "user-id"};
    for (size_t i = 0; i < 3; ++i)
    {
        unsigned count = 0;
        if (! jsonObjectFieldStringsAreExact(item, keys[i]))
            *invalid = true;
        for (const cJSON *field = item->child; field != NULL; field = field->next)
            if (field->string != NULL && strcmp(field->string, keys[i]) == 0 && ++count > 1)
                *invalid = true;
    }
    if (*invalid)
        return NULL;
    const cJSON *uuid        = cJSON_GetObjectItemCaseSensitive(item, "uuid");
    const cJSON *id          = cJSON_GetObjectItemCaseSensitive(item, "id");
    const cJSON *user_id     = cJSON_GetObjectItemCaseSensitive(item, "user-id");
    uint32_t     field_count = (uuid != NULL ? 1U : 0U) + (id != NULL ? 1U : 0U) + (user_id != NULL ? 1U : 0U);
    if (field_count > 1U)
    {
        LOGF("JSON Error: VmessServer->settings->%s object must use only one of uuid, id, or user-id", path);
        *invalid = true;
        return NULL;
    }

    if (uuid != NULL)
    {
        return uuid;
    }

    if (id != NULL)
    {
        return id;
    }

    return user_id;
}

static bool vmessserverParseUserEntry(vmessserver_tstate_t *ts, const cJSON *item, const char *path)
{
    if (cJSON_IsString(item))
    {
        return vmessserverParseUuidValue(ts, item, path, NULL);
    }

    if (! cJSON_IsObject(item))
    {
        LOGF("JSON Error: VmessServer->settings->%s must be a UUID string or object", path);
        return false;
    }

    bool         uuid_invalid = false;
    const cJSON *uuid         = vmessserverGetObjectUuidField(item, path, &uuid_invalid);
    if (uuid_invalid)
    {
        return false;
    }
    if (uuid == NULL)
    {
        LOGF("JSON Error: VmessServer->settings->%s object must contain uuid, id, or user-id", path);
        return false;
    }

    const cJSON *username      = cJSON_GetObjectItemCaseSensitive(item, "username");
    const char  *username_text = NULL;
    if (username != NULL)
    {
        if (! cJSON_IsString(username) || username->valuestring == NULL || username->valuestring[0] == '\0')
        {
            LOGF("JSON Error: VmessServer->settings->%s->username must be a non-empty string when provided", path);
            return false;
        }
        username_text = username->valuestring;
    }

    return vmessserverParseUuidValue(ts, uuid, path, username_text);
}

static bool vmessserverParseUuidArray(vmessserver_tstate_t *ts, const cJSON *array, const char *path)
{
    if (! cJSON_IsArray(array) || cJSON_GetArraySize(array) <= 0)
    {
        LOGF("JSON Error: VmessServer->settings->%s must be a non-empty array", path);
        return false;
    }

    int    index = 0;
    cJSON *item  = NULL;
    cJSON_ArrayForEach(item, array)
    {
        char item_path[64] = {0};
        snprintf(item_path, sizeof(item_path), "%s[%d]", path, index);
        if (! vmessserverParseUserEntry(ts, item, item_path))
        {
            return false;
        }
        ++index;
    }

    return true;
}

static bool vmessserverParseUsers(vmessserver_tstate_t *ts, const cJSON *settings)
{
    bool         invalid = false;
    const cJSON *uuid    = vmessserverGetObjectUuidField(settings, "credentials", &invalid);
    if (invalid)
        return false;

    if (uuid != NULL && ! vmessserverParseUuidValue(ts, uuid, uuid->string != NULL ? uuid->string : "uuid", NULL))
    {
        return false;
    }

    const cJSON *uuids = cJSON_GetObjectItemCaseSensitive(settings, "uuids");
    if (uuids != NULL && ! vmessserverParseUuidArray(ts, uuids, "uuids"))
    {
        return false;
    }

    const cJSON *users   = cJSON_GetObjectItemCaseSensitive(settings, "users");
    const cJSON *clients = cJSON_GetObjectItemCaseSensitive(settings, "clients");
    if (users != NULL && clients != NULL)
    {
        LOGF("JSON Error: VmessServer->settings must use either users or clients, not both");
        return false;
    }

    if (users != NULL && ! vmessserverParseUuidArray(ts, users, "users"))
    {
        return false;
    }

    if (clients != NULL && ! vmessserverParseUuidArray(ts, clients, "clients"))
    {
        return false;
    }

    if (ts->user_count == 0)
    {
        LOGF("JSON Error: VmessServer->settings requires at least one uuid, uuids, users, or clients entry");
        return false;
    }

    return true;
}

static bool vmessserverHasLocalUserSettings(const cJSON *settings)
{
    return cJSON_GetObjectItemCaseSensitive(settings, "uuid") != NULL ||
           cJSON_GetObjectItemCaseSensitive(settings, "id") != NULL ||
           cJSON_GetObjectItemCaseSensitive(settings, "user-id") != NULL ||
           cJSON_GetObjectItemCaseSensitive(settings, "uuids") != NULL ||
           cJSON_GetObjectItemCaseSensitive(settings, "users") != NULL ||
           cJSON_GetObjectItemCaseSensitive(settings, "clients") != NULL;
}

static bool vmessserverParseAuthMode(vmessserver_tstate_t *ts, tunnel_t *t, node_t *node, const cJSON *settings)
{
    const cJSON *auth_node_json = cJSON_GetObjectItemCaseSensitive(settings, "auth-client-node-name");

    if (auth_node_json == NULL)
    {
        return vmessserverParseUsers(ts, settings);
    }

    if (! cJSON_IsString(auth_node_json) || auth_node_json->valuestring == NULL ||
        auth_node_json->valuestring[0] == '\0')
    {
        LOGF("JSON Error: VmessServer->settings->auth-client-node-name (string field) must be a non-empty string");
        return false;
    }

    if (vmessserverHasLocalUserSettings(settings))
    {
        LOGF("JSON Error: VmessServer auth-client mode uses the AuthenticationClient users database; remove local "
             "uuid/uuids/users/clients settings");
        return false;
    }

    if (! vmessserverParseAuthClientNode(ts, node, auth_node_json->valuestring))
    {
        return false;
    }

    return vmessserverCreateUserControllerTunnel(t, node);
}

static bool vmessserverParseMaturity(vmessserver_tstate_t *ts, const cJSON *settings)
{
    static const char *const fields[] = {"encrypted-counter-policy",
                                         "allowed-security",
                                         "send-termination",
                                         "packetaddr",
                                         "packetaddr-max-destinations",
                                         "verbose"};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i)
    {
        unsigned count = 0;
        if (! jsonObjectFieldStringsAreExact(settings, fields[i]))
            return false;
        for (const cJSON *field = settings->child; field != NULL; field = field->next)
            if (field->string != NULL && strcmp(field->string, fields[i]) == 0 && ++count > 1)
                return false;
    }
    ts->counter_policy              = kVmessCounterWrap;
    ts->send_termination            = true;
    ts->packetaddr                  = true;
    ts->packetaddr_max_destinations = 64;
    ts->allowed_security            = 15;
    const cJSON *policy             = cJSON_GetObjectItemCaseSensitive(settings, "encrypted-counter-policy");
    if (policy != NULL)
    {
        if (! cJSON_IsString(policy))
            return false;
        if (strcmp(policy->valuestring, "strict") == 0)
            ts->counter_policy = kVmessCounterStrict;
        else if (strcmp(policy->valuestring, "wrap") != 0)
            return false;
    }
    const char *const booleans[] = {"send-termination", "packetaddr", "verbose"};
    bool             *outputs[]  = {&ts->send_termination, &ts->packetaddr, &ts->verbose};
    for (unsigned i = 0; i < 3; ++i)
    {
        const cJSON *value = cJSON_GetObjectItemCaseSensitive(settings, booleans[i]);
        if (value != NULL)
        {
            if (! cJSON_IsBool(value))
                return false;
            *outputs[i] = cJSON_IsTrue(value);
        }
    }
    int64_t limit = 64;
    if (jsonGetObjectIntegerInRange(settings, "packetaddr-max-destinations", 1, 1024, &limit) == kJsonValueInvalid)
        return false;
    ts->packetaddr_max_destinations = (uint16_t) limit;
    const cJSON *allowed            = cJSON_GetObjectItemCaseSensitive(settings, "allowed-security");
    if (allowed != NULL)
    {
        if (! cJSON_IsArray(allowed) || allowed->child == NULL)
            return false;
        ts->allowed_security = 0;
        for (const cJSON *value = allowed->child; value != NULL; value = value->next)
        {
            if (! cJSON_IsString(value) || value->valuestring == NULL ||
                (value->type & cJSON_StringHasEmbeddedNul) != 0 ||
                ! configLexicalCheckEncodingQuiet(value->valuestring, strlen(value->valuestring)))
                return false;
            const char *const modes[] = {"aes-128-gcm", "chacha20-poly1305", "none", "zero"};
            unsigned          mode    = 0;
            while (mode < 4 && strcmp(value->valuestring, modes[mode]) != 0)
                ++mode;
            if (mode == 4 || (ts->allowed_security & (1U << mode)) != 0)
                return false;
            if (mode < 2 &&
                ! vmessCipherAvailable(mode == 0 ? VMESS_SECURITY_AES128_GCM : VMESS_SECURITY_CHACHA20_POLY1305))
                return false;
            ts->allowed_security |= (uint8_t) (1U << mode);
        }
    }
    /* Raw zero cannot represent UDP datagram boundaries. */
    return ts->allow_connect || (ts->allowed_security & 7U) != 0;
}

tunnel_t *vmessserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(vmessserver_tstate_t), sizeof(vmessserver_lstate_t));
    if (! t)
    {
        return NULL;
    }

    vmessserver_tstate_t *ts       = tunnelGetState(t);
    const cJSON          *settings = node->node_settings_json;
#define VMESS_INIT_STATS(field) atomic_init(&ts->stats.field, 0)
    VMESS_INIT_STATS(applications);
    VMESS_INIT_STATS(carriers);
    VMESS_INIT_STATS(backends);
    VMESS_INIT_STATS(tx_records);
    VMESS_INIT_STATS(rx_records);
    VMESS_INIT_STATS(tx_application_bytes);
    VMESS_INIT_STATS(rx_application_bytes);
    VMESS_INIT_STATS(tx_wire_bytes);
    VMESS_INIT_STATS(rx_wire_bytes);
    VMESS_INIT_STATS(wrap_events);
    VMESS_INIT_STATS(strict_exhaustion);
    VMESS_INIT_STATS(next_log_ms);
#undef VMESS_INIT_STATS
    for (unsigned i = 0; i < kVmessServerReasonCount; ++i)
        atomic_init(&ts->stats.reasons[i], 0);

    t->fnInitU    = &vmessserverTunnelUpStreamInit;
    t->fnFinU     = &vmessserverTunnelUpStreamFinish;
    t->fnPayloadU = &vmessserverTunnelUpStreamPayload;
    t->fnPauseU   = &vmessserverTunnelUpStreamPause;
    t->fnResumeU  = &vmessserverTunnelUpStreamResume;
    t->fnEstD     = &vmessserverTunnelDownStreamEst;
    t->fnFinD     = &vmessserverTunnelDownStreamFinish;
    t->fnPayloadD = &vmessserverTunnelDownStreamPayload;
    t->fnPauseD   = &vmessserverTunnelDownStreamPause;
    t->fnResumeD  = &vmessserverTunnelDownStreamResume;

    t->onQuiesceRequest = vmessserverAuthOnQuiesceRequest;
    t->onWorkerQuiesce  = vmessserverAuthOnWorkerQuiesce;
    t->onWorkerStop     = vmessserverAuthOnWorkerStop;
    t->onPrepare        = &vmessserverTunnelOnPrepair;
    t->onDestroy        = &vmessserverTunnelDestroy;

    if (! nodeHasNext(node))
    {
        LOGF("VmessServer: a next node is required for accepted VMESS traffic");
        vmessserverTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: VmessServer->settings (object field) : The object was empty or invalid");
        vmessserverTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    ts->allow_connect                        = true;
    ts->allow_udp                            = true;
    int fallback_intentional_delay_ms        = kVmessServerDefaultFallbackIntentionalDelayMs;
    int fallback_intentional_delay_jitter_ms = kVmessServerDefaultFallbackIntentionalDelayJitterMs;
    getBoolFromJsonObjectOrDefault(&ts->allow_connect, settings, "connect", true);
    getBoolFromJsonObjectOrDefault(&ts->allow_udp, settings, "udp", true);
    getBoolFromJsonObjectOrDefault(&ts->verbose, settings, "verbose", false);
    getIntFromJsonObjectOrDefault(&fallback_intentional_delay_ms,
                                  settings,
                                  "fallback-intentional-delay-ms",
                                  kVmessServerDefaultFallbackIntentionalDelayMs);
    getIntFromJsonObjectOrDefault(&fallback_intentional_delay_jitter_ms,
                                  settings,
                                  "fallback-intentional-delay-jitter-ms",
                                  kVmessServerDefaultFallbackIntentionalDelayJitterMs);

    if (! ts->allow_connect && ! ts->allow_udp)
    {
        LOGF("JSON Error: VmessServer must enable at least one of connect/udp");
        vmessserverTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    if (! vmessserverParseMaturity(ts, settings))
    {
        LOGF("VmessServer: invalid body policy, packetaddr, termination or diagnostic setting");
        vmessserverTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    if (fallback_intentional_delay_ms < 0)
    {
        LOGF("JSON Error: VmessServer->settings->fallback-intentional-delay-ms (number field) : The value was invalid");
        vmessserverTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }
    ts->fallback_replay_config.delay_ms        = (uint32_t) fallback_intentional_delay_ms;
    ts->fallback_replay_config.max_batch_bytes = kVmessServerMaxPendingBytes;

    if (fallback_intentional_delay_jitter_ms < 0)
    {
        LOGF("JSON Error: VmessServer->settings->fallback-intentional-delay-jitter-ms (number field) : The value was "
             "invalid");
        vmessserverTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }
    ts->fallback_replay_config.jitter_ms = (uint32_t) fallback_intentional_delay_jitter_ms;

    if (ts->fallback_replay_config.delay_ms == 0 && ts->fallback_replay_config.jitter_ms > 0)
    {
        LOGD("VmessServer: fallback-intentional-delay-jitter-ms is ignored because fallback-intentional-delay-ms is 0");
    }

    const struct
    {
        const char *name;
        int64_t     value;
    } defaults[] = {{"handshake-timeout-ms", 10000},
                    {"auth-max-pending", 4096},
                    {"auth-pending-max-bytes", 64 * 1024 * 1024},
                    {"auth-cache-max-bytes", 64 * 1024 * 1024},
                    {"replay-max-entries", 262144}};
    size_t values[5];
    for (size_t i = 0; i < sizeof(defaults) / sizeof(defaults[0]); ++i)
    {
        int64_t value = defaults[i].value;
        if (jsonGetObjectIntegerInRange(settings, defaults[i].name, 1, INT_MAX, &value) == kJsonValueInvalid)
        {
            LOGF("VmessServer: %s must be an integer in 1..INT_MAX", defaults[i].name);
            vmessserverTunnelDestroy(t, wwLifecycleStartupRollback());
            return NULL;
        }
        values[i] = (size_t) value;
    }
    ts->handshake_timeout_ms   = (uint32_t) values[0];
    ts->auth_max_pending       = values[1];
    ts->auth_pending_max_bytes = values[2];
    ts->auth_cache_max_bytes   = values[3];
    ts->replay_max_entries     = values[4];
    if (ts->replay_max_entries > SIZE_MAX / 256U)
    {
        LOGF("VmessServer: replay-max-entries exceeds host table geometry");
        vmessserverTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    if (! vmessserverParseAuthMode(ts, t, node, settings) || ! vmessserverParseFallbackNode(ts, node, settings))
    {
        vmessserverTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    if (ts->auth_client_node != NULL || ts->fallback_node != NULL)
    {
        t->onChain = &vmessserverTunnelOnChain;
    }

    ts->replay         = vmessReplayCreate(ts->replay_max_entries);
    ts->owned_backends = memoryAllocateZero((size_t) getWorkersCount() * sizeof(*ts->owned_backends));
    ts->auth           = vmessserverAuthCreate(t);
    if (ts->auth == NULL)
    {
        LOGF("VmessServer: failed to initialize authentication runtime");
        vmessserverTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }
    if (! vmessserverRegisterApi(t))
    {
        vmessserverTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }
    return t;
}
