#include "modules/push_user_stats/push_user_stats.h"
#include "loggers/network_logger.h"

typedef struct stats_entry_s
{
    uint64_t id, upload, download;
    user_t  *user;
} stats_entry_t;

static int compareEntries(const void *left, const void *right)
{
    const stats_entry_t *a = left, *b = right;
    return (a->id > b->id) - (a->id < b->id);
}

static sbuf_t *acknowledge(line_t *l, const uint8_t correlation_id[4], const authenticationserver_auth_client_t *client)
{
    char epoch[65] = {0}, digest[65] = {0};
    memoryCopy(epoch, client->accounting_epoch, 64);
    asciiHexEncodeBytesLower(client->last_digest, sizeof(client->last_digest), (uint8_t *) digest);
    cJSON  *json = cJSON_CreateObject();
    discard cJSON_AddStringToObject(json, "epoch", epoch);
    discard jsonAddUint64ToObject(json, "sequence", client->last_sequence);
    discard cJSON_AddStringToObject(json, "digest", digest);
    /* Exact replay preserves the authoritative totals/first-use refresh. */
    discard cJSON_AddBoolToObject(json, "needs-pull", true);
    char   *text = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    sbuf_t *response = authenticationserverCreateResponseFrame(
        l, kAuthenticationServerResponseTypeOk, correlation_id, (const uint8_t *) text, (uint32_t) stringLength(text));
    cJSON_free(text);
    return response;
}

sbuf_t *authenticationserverPushUserStatsHandle(const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
                                                tunnel_t *t, line_t *l, authenticationserver_session_t *session,
                                                const uint8_t *request_data, uint32_t request_data_len)
{
    authenticationserver_tstate_t      *ts       = tunnelGetState(t);
    authenticationserver_auth_client_t *client   = session->accounting_client;
    cJSON                              *json     = cJSON_ParseWithLength((const char *) request_data, request_data_len);
    const cJSON                        *epoch    = cJSON_GetObjectItemCaseSensitive(json, "epoch");
    uint64_t                            sequence = 0;
    const char                         *error    = "invalid-usage-batch";
    stats_entry_t                      *entries  = NULL;
    sha256_hash_t                       digest;
    if (! cJSON_IsObject(json) || ! cJSON_IsString(epoch) || epoch->valuestring == NULL ||
        stringLength(epoch->valuestring) != 64 ||
        ! getUint64FromJson(&sequence, cJSON_GetObjectItemCaseSensitive(json, "sequence")) || sequence == 0)
        goto rejected;
    if (client == NULL || ! memoryEqual(session->accounting_epoch, client->accounting_epoch, 64) ||
        ! memoryEqual(epoch->valuestring, client->accounting_epoch, 64))
    {
        error = "accounting-continuity-lost";
        goto rejected;
    }
    if (wCryptoSHA256(&digest, request_data, request_data_len) != kWCryptoOk)
    {
        error = "usage-digest-failed";
        goto rejected;
    }
    if (sequence == client->last_sequence)
    {
        if (! memoryEqual(digest.bytes, client->last_digest, sizeof(client->last_digest)))
        {
            error = "usage-replay-conflict";
            goto rejected;
        }
        cJSON_Delete(json);
        return acknowledge(l, correlation_id, client);
    }
    if (client->last_sequence == UINT64_MAX || sequence != client->last_sequence + 1)
    {
        error = "usage-sequence-invalid";
        goto rejected;
    }
    const cJSON *array = cJSON_GetObjectItemCaseSensitive(json, "users");
    const int    count = cJSON_GetArraySize(array);
    if (! cJSON_IsArray(array) || count <= 0 || count > kAuthenticationServerMaxBatchEntries)
        goto rejected;
    size_t bytes;
    if (! memoryTryComputeArraySize((size_t) count, sizeof(*entries), &bytes))
        goto rejected;
    entries = memoryAllocate(bytes);
    const cJSON *entry;
    size_t       index = 0;
    cJSON_ArrayForEach(entry, array)
    {
        stats_entry_t *current = &entries[index++];
        if (! cJSON_IsObject(entry) ||
            ! getUint64FromJson(&current->id, cJSON_GetObjectItemCaseSensitive(entry, "id")) || current->id == 0 ||
            ! getUint64FromJson(&current->upload, cJSON_GetObjectItemCaseSensitive(entry, "up")) ||
            ! getUint64FromJson(&current->download, cJSON_GetObjectItemCaseSensitive(entry, "down")) ||
            (current->upload == 0 && current->download == 0))
            goto rejected;
        current->user = usersLookupByIdentifier(&ts->store.users, current->id);
        if (current->user == NULL)
            goto rejected;
    }
    qsort(entries, (size_t) count, sizeof(*entries), compareEntries);
    for (int i = 1; i < count; ++i)
        if (entries[i - 1].id == entries[i].id)
            goto rejected;

    /* state_lock serializes validation, mutation and checkpoint publication.
     * All fallible preconditions precede these infallible per-user operations. */
    const uint64_t first_use = getTimeOfDayMS();
    for (int i = 0; i < count; ++i)
    {
        userAddTraffic(entries[i].user, entries[i].upload, entries[i].download);
        userMarkFirstUsage(entries[i].user, first_use);
    }
    authenticationserverBumpStatsRevision(t);
    client->last_sequence = sequence;
    memoryCopy(client->last_digest, digest.bytes, sizeof(client->last_digest));
    memoryFree(entries);
    cJSON_Delete(json);
    return acknowledge(l, correlation_id, client);

rejected:
    memoryFree(entries);
    cJSON_Delete(json);
    return authenticationserverCreateErrorResponseFrame(l, correlation_id, error);
}
