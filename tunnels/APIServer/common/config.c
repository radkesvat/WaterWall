#include "APIServer/structure.h"

static bool knownKeys(const cJSON *object, const char *const *names, size_t count)
{
    if (! cJSON_IsObject(object))
        return false;
    for (const cJSON *item = object->child; item; item = item->next)
    {
        size_t i = 0;
        for (; i < count; ++i)
            if (strcmp(item->string, names[i]) == 0)
                break;
        if (i == count)
            return false;
        for (const cJSON *prior = object->child; prior != item; prior = prior->next)
            if (strcmp(prior->string, item->string) == 0)
                return false;
    }
    return true;
}

static const char *label(const cJSON *object, const char *key, size_t bound)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, key);
    if (! cJSON_IsString(item) || ! *item->valuestring || strlen(item->valuestring) > bound ||
        strcmp(item->valuestring, "*") == 0)
        return NULL;
    return item->valuestring;
}

static bool limit(const cJSON *json, const char *key, size_t default_value, size_t maximum, size_t *dest)
{
    int64_t             n;
    json_value_status_t status = jsonGetObjectIntegerInRange(json, key, 1, (int64_t) maximum, &n);
    if (status == kJsonValueInvalid)
        return false;
    *dest = status == kJsonValueMissing ? default_value : (size_t) n;
    return true;
}

bool apiserverLoadSettings(apiserver_tstate_t *ts, const cJSON *settings)
{
    static const char *const settings_keys[]   = {"clients",
                                                  "max_request_envelope",
                                                  "max_response_envelope",
                                                  "max_input_bytes",
                                                  "max_line_memory",
                                                  "max_input_fragments",
                                                  "max_queued_requests",
                                                  "max_sessions",
                                                  "max_jobs",
                                                  "handler_working_memory",
                                                  "max_memory",
                                                  "frame_timeout_ms",
                                                  "request_timeout_ms",
                                                  "output_timeout_ms",
                                                  "idle_timeout_ms"};
    static const char *const client_keys[]     = {"name", "token", "allow"};
    static const char *const permission_keys[] = {"config", "node", "operations"};
    const size_t             mib               = 1024U * 1024U;
    api_limits_t            *l                 = &ts->limits;
    if (! knownKeys(settings, settings_keys, sizeof(settings_keys) / sizeof(*settings_keys)) ||
        ! limit(settings, "max_request_envelope", mib, 64 * mib, &l->max_request_envelope) ||
        ! limit(settings, "max_response_envelope", mib, 64 * mib, &l->max_response_envelope) ||
        ! limit(settings, "max_input_bytes", 2 * mib, 256 * mib, &l->max_input_bytes) ||
        ! limit(settings, "max_line_memory", 8 * mib, 1024 * mib, &l->max_line_memory) ||
        ! limit(settings, "max_input_fragments", 256, 65536, &l->max_input_fragments) ||
        ! limit(settings, "max_queued_requests", 8, 1024, &l->max_queued_requests) ||
        ! limit(settings, "max_sessions", 256, 65536, &l->max_sessions) ||
        ! limit(settings, "max_jobs", 64, 65536, &l->max_jobs) ||
        ! limit(settings, "handler_working_memory", 8 * mib, 1024 * mib, &l->handler_working_memory) ||
        ! limit(settings, "max_memory", 64 * mib, 2048 * mib, &l->max_memory))
        return false;
    size_t timeout;
#define API_TIMEOUT(field, value)                                                                                      \
    if (! limit(settings, #field, value, UINT32_MAX, &timeout))                                                        \
        return false;                                                                                                  \
    l->field = (uint32_t) timeout
    API_TIMEOUT(frame_timeout_ms, 15000);
    API_TIMEOUT(request_timeout_ms, 10000);
    API_TIMEOUT(output_timeout_ms, 15000);
    API_TIMEOUT(idle_timeout_ms, 60000);
#undef API_TIMEOUT
    /* Peak body storage is three envelopes during JSON/body parsing; geometric
     * growth holds old plus new capacities (at most two envelopes) first. Keep
     * both peaks alongside hard input, output, and carrier/metadata headroom.
     * Aggregate also admits one fully reserved handler. */
    uint64_t frame_growth_geometry = 2ULL * (l->max_request_envelope + 1);
    uint64_t frame_parse_geometry  = 3ULL * l->max_request_envelope + 2;
    uint64_t line_geometry =
        l->max_input_bytes + max(frame_growth_geometry, frame_parse_geometry) + l->max_response_envelope + 128U * 1024U;
    uint64_t job_geometry =
        l->handler_working_memory + 2ULL * l->max_request_envelope + 2ULL * l->max_response_envelope + 128U * 1024U;
    if (l->max_input_bytes < l->max_request_envelope + 4 || l->max_line_memory < line_geometry ||
        l->max_response_envelope < 1024 ||
        l->handler_working_memory < kApiMinimumResultAllowance + kApiHandlerMetadataAllowance ||
        l->max_memory < l->max_line_memory + job_geometry)
        return false;
    const cJSON *clients      = cJSON_GetObjectItemCaseSensitive(settings, "clients");
    int          client_count = cJSON_GetArraySize(clients);
    if (! cJSON_IsArray(clients) || client_count < 1 || client_count > 256)
        return false;
    for (const cJSON *entry = clients->child; entry; entry = entry->next)
    {
        const char *name  = label(entry, "name", 256);
        const char *token = label(entry, "token", 64);
        uint8_t     bytes[32];
        if (! knownKeys(entry, client_keys, 3) || ! name || ! apiserverTokenDecode(token, bytes))
            return false;
        for (api_client_t *prior = ts->clients; prior; prior = prior->next)
            if (strcmp(prior->name, name) == 0 || wCryptoEqual(prior->token, bytes, sizeof(bytes)))
                return false;
        api_client_t *client = memoryAllocateZero(sizeof(*client));
        client->name         = stringDuplicate(name);
        memcpy(client->token, bytes, sizeof(bytes));
        client->next       = ts->clients;
        ts->clients        = client;
        const cJSON *allow = cJSON_GetObjectItemCaseSensitive(entry, "allow");
        int          count = cJSON_GetArraySize(allow);
        if (! cJSON_IsArray(allow) || count < 1 || count > 512)
            return false;
        for (const cJSON *permission = allow->child; permission; permission = permission->next)
        {
            const char  *config          = label(permission, "config", 256);
            const char  *node            = label(permission, "node", 256);
            const cJSON *operations      = cJSON_GetObjectItemCaseSensitive(permission, "operations");
            int          operation_count = cJSON_GetArraySize(operations);
            if (! knownKeys(permission, permission_keys, 3) || ! config || ! node || ! cJSON_IsArray(operations) ||
                operation_count < 1 || operation_count > 64)
                return false;
            for (const cJSON *op = operations->child; op; op = op->next)
            {
                if (! cJSON_IsString(op) || ! *op->valuestring || strlen(op->valuestring) > 64 ||
                    strcmp(op->valuestring, "*") == 0)
                    return false;
                api_permission_t *p = memoryAllocateZero(sizeof(*p));
                p->config           = stringDuplicate(config);
                p->node             = stringDuplicate(node);
                p->operation        = stringDuplicate(op->valuestring);
                p->next             = client->permissions;
                client->permissions = p;
            }
        }
    }
    return true;
}

void apiserverFreeSettings(apiserver_tstate_t *ts)
{
    while (ts->clients)
    {
        api_client_t *client = ts->clients;
        ts->clients          = client->next;
        while (client->permissions)
        {
            api_permission_t *p = client->permissions;
            client->permissions = p->next;
            memoryFree(p->config);
            memoryFree(p->node);
            memoryFree(p->operation);
            memoryFree(p);
        }
        memoryFree(client->name);
        memoryFree(client);
    }
}
