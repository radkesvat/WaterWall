#include "modules/push_user_stats/push_user_stats.h"
#include "loggers/network_logger.h"

typedef struct stats_entry_s
{
    uint64_t id, upload, download, first_usage;
    user_t  *user;
} stats_entry_t;

static int compareEntries(const void *left, const void *right)
{
    const stats_entry_t *a = left, *b = right;
    return (a->id > b->id) - (a->id < b->id);
}

static bool hasBatchFields(const cJSON *object, bool root)
{
    static const char *const root_fields[]  = {"epoch", "sequence", "users"};
    static const char *const entry_fields[] = {"id", "up", "down", "first-usage-at-ms"};
    const char *const       *fields         = root ? root_fields : entry_fields;
    if (! cJSON_IsObject(object))
        return false;
    unsigned     count = 0;
    const unsigned required = root ? 3U : 4U;
    const cJSON *field;
    cJSON_ArrayForEach(field, object)
    {
        if (++count > required ||
            (stringCompare(field->string, fields[0]) != 0 && stringCompare(field->string, fields[1]) != 0 &&
             stringCompare(field->string, fields[2]) != 0 && (root || stringCompare(field->string, fields[3]) != 0)))
            return false;
    }
    /* The lexical parser rejects duplicate decoded names. */
    return count == required;
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

static void statsExactNumber(cJSON *object, const char *key, uint64_t value)
{
    char text[24];
    snprintf(text, sizeof(text), "%" PRIu64, value);
    discard cJSON_AddStringToObject(object, key, text);
}

/* This correlated refusal proves that the exact next batch was not committed.
 * The client can preserve every obligation, release its immutable attempt and
 * rebuild at the same sequence after refreshing account membership. */
static sbuf_t *missingAccounts(line_t *line, const uint8_t correlation_id[4],
                               const authenticationserver_auth_client_t *client, uint64_t sequence,
                               const sha256_hash_t *digest, const stats_entry_t *entries, size_t count)
{
    char epoch[65] = {0}, attempt[65] = {0}, checkpoint[65] = {0};
    memoryCopy(epoch, client->accounting_epoch, 64);
    asciiHexEncodeBytesLower(digest->bytes, sizeof(digest->bytes), (uint8_t *) attempt);
    asciiHexEncodeBytesLower(client->last_digest, sizeof(client->last_digest), (uint8_t *) checkpoint);
    cJSON  *json = cJSON_CreateObject();
    discard cJSON_AddStringToObject(json, "error", "usage-accounts-missing");
    discard cJSON_AddStringToObject(json, "epoch", epoch);
    statsExactNumber(json, "sequence", sequence);
    discard cJSON_AddStringToObject(json, "digest", attempt);
    statsExactNumber(json, "checkpoint-sequence", client->last_sequence);
    discard cJSON_AddStringToObject(json, "checkpoint-digest", checkpoint);
    cJSON  *missing = cJSON_AddArrayToObject(json, "missing-ids");
    for (size_t i = 0; i < count; ++i)
        if (entries[i].user == NULL)
        {
            char id[24];
            snprintf(id, sizeof(id), "%" PRIu64, entries[i].id);
            discard cJSON_AddItemToArray(missing, cJSON_CreateString(id));
        }
    char   *text     = cJSON_PrintUnformatted(json);
    sbuf_t *response = authenticationserverCreateResponseFrame(
        line, kAuthenticationServerResponseTypeError, correlation_id, (const uint8_t *) text, (uint32_t) strlen(text));
    cJSON_free(text);
    cJSON_Delete(json);
    return response;
}

sbuf_t *authenticationserverPushUserStatsHandle(const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
                                                tunnel_t *t, line_t *l, authenticationserver_session_t *session,
                                                const uint8_t *request_data, uint32_t request_data_len)
{
    authenticationserver_tstate_t      *ts       = tunnelGetState(t);
    authenticationserver_auth_client_t *client   = session->accounting_client;
    /* Root plus three key/value pairs, then each row's object and four pairs.
     * Bound the tree before allocation, including malformed wide arrays. */
    cJSON *json = configLexicalParseBoundedQuiet(
        (const char *) request_data, request_data_len, 3, 7U + 9U * kAuthenticationServerMaxBatchEntries);
    const cJSON                        *epoch    = cJSON_GetObjectItemCaseSensitive(json, "epoch");
    uint64_t                            sequence = 0;
    const char                         *error    = "invalid-usage-batch";
    stats_entry_t                      *entries  = NULL;
    sha256_hash_t                       digest;
    if (! hasBatchFields(json, true) || ! cJSON_IsString(epoch) || epoch->valuestring == NULL ||
        stringLength(epoch->valuestring) != 64 ||
        ! getUint64FromJson(&sequence, cJSON_GetObjectItemCaseSensitive(json, "sequence")) || sequence == 0)
        goto rejected;
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
        if (! hasBatchFields(entry, false) ||
            ! getUint64FromJson(&current->id, cJSON_GetObjectItemCaseSensitive(entry, "id")) || current->id == 0 ||
            ! getUint64FromJson(&current->upload, cJSON_GetObjectItemCaseSensitive(entry, "up")) ||
            ! getUint64FromJson(&current->download, cJSON_GetObjectItemCaseSensitive(entry, "down")) ||
            ! getUint64FromJson(&current->first_usage, cJSON_GetObjectItemCaseSensitive(entry, "first-usage-at-ms")) ||
            current->first_usage == 0)
            goto rejected;
    }
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
        memoryFree(entries);
        cJSON_Delete(json);
        return acknowledge(l, correlation_id, client);
    }
    if (client->last_sequence == UINT64_MAX || sequence != client->last_sequence + 1)
    {
        error = "usage-sequence-invalid";
        goto rejected;
    }
    qsort(entries, (size_t) count, sizeof(*entries), compareEntries);
    for (int i = 1; i < count; ++i)
        if (entries[i - 1].id == entries[i].id)
            goto rejected;
    /* Account existence applies only to a new batch. Exact replay remains
     * acknowledgeable after an accepted account is edited or removed. */
    bool missing = false;
    for (int i = 0; i < count; ++i)
    {
        stats_entry_t *current = &entries[i];
        current->user = usersLookupByIdentifier(&ts->store.users, current->id);
        missing |= current->user == NULL;
    }
    if (missing)
    {
        sbuf_t *response = missingAccounts(l, correlation_id, client, sequence, &digest, entries, (size_t) count);
        memoryFree(entries);
        cJSON_Delete(json);
        return response;
    }

    /* state_lock serializes validation, mutation and checkpoint publication.
     * All fallible preconditions precede these infallible per-user operations. */
    const uint64_t accounting_now = authenticationserverAccountingTimeMS(ts);
    for (int i = 0; i < count; ++i)
    {
        userAddTraffic(entries[i].user, entries[i].upload, entries[i].download);
        userMergeFirstUsage(entries[i].user, min(entries[i].first_usage, accounting_now));
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
