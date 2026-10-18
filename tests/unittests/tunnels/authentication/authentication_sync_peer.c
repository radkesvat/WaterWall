/* Server half shared by the paired authentication sync and ingress fixtures. */
#include "authentication_sync_peer.h"
#include "AuthenticationServer/api.h"
#include "AuthenticationServer/structure.h"
#include "test_assert.h"
#define require(c, m) TEST_REQUIRE(TEST_FAILURE_EXIT, c, m)

tunnel_t *authTestPeerCreate(uint32_t offset)
{
    tunnel_t *t = tunnelCreate(NULL, sizeof(authenticationserver_tstate_t), sizeof(authenticationserver_lstate_t));
    require(t != NULL, "peer allocation failed");
    t->lstate_offset                  = offset;
    t->fnInitU                        = authenticationserverTunnelUpStreamInit;
    t->fnPayloadU                     = authenticationserverTunnelUpStreamPayload;
    t->fnFinU                         = authenticationserverTunnelUpStreamFinish;
    t->fnPauseU                       = authenticationserverTunnelUpStreamPause;
    t->fnResumeU                      = authenticationserverTunnelUpStreamResume;
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    authenticationserverInitializeAccountingClock(ts);
    rwlockinit(&ts->state_lock);
    require(usersCreate(&ts->store.users), "peer users failed");
    ts->store.config_revision = ts->store.stats_revision = 1;
    ts->auth_clients_count                               = 2;
    ts->auth_clients                                     = memoryCalloc(2, sizeof(*ts->auth_clients));
    for (unsigned i = 0; i < 2; ++i)
    {
        ts->auth_clients[i].name             = stringDuplicate(i == 0 ? "edge-a" : "edge-b");
        ts->auth_clients[i].secret           = stringDuplicate("secret");
        ts->auth_clients[i].allow_stats_push = ts->auth_clients[i].allow_user_pull = true;
        ts->auth_clients[i].session_idle_timeout_ms                                = 1000;
    }
    authTestPeerPopulate(t, 1);
    return t;
}
uint32_t authTestPeerLineSize(void)
{
    return tunnelGetCorrectAlignedLineStateSize(sizeof(authenticationserver_lstate_t));
}
void authTestPeerDestroy(tunnel_t *t)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    nodeApiUnregister(t);
    authenticationserverSessionsDestroy(ts);
    authenticationserverAuthClientsDestroy(ts);
    usersDestroy(&ts->store.users);
    rwlockDestroy(&ts->state_lock);
    tunnelDestroy(t);
}
user_stat_t authTestPeerStats(tunnel_t *t, uint64_t id)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    user_stat_t                    stats;
    rwlockReadLock(&ts->state_lock);
    user_t *user = usersLookupByIdentifier(&ts->store.users, id);
    require(user != NULL, "peer user absent");
    userGetStats(user, &stats);
    rwlockReadUnlock(&ts->state_lock);
    return stats;
}
uint64_t authTestPeerFirstUse(tunnel_t *t)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    user_time_info_t               info;
    userGetTimeInfo(usersLookupByIdentifier(&ts->store.users, 42), &info);
    return info.first_usage_at_ms;
}
void authTestPeerExpireSessions(tunnel_t *t)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    rwlockWriteLock(&ts->state_lock);
    for (uint32_t i = 0; i < ts->sessions_count; ++i)
        atomicStoreRelaxed(&ts->sessions[i]->last_activity_ms, getTickMS() - 2000);
    rwlockWriteUnlock(&ts->state_lock);
    authenticationserverSessionsExpireIdle(t);
}
void authTestPeerLoseEpoch(tunnel_t *t, unsigned client)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    rwlockWriteLock(&ts->state_lock);
    memoryZero(ts->auth_clients[client].accounting_epoch, 64);
    ts->auth_clients[client].last_sequence = 0;
    rwlockWriteUnlock(&ts->state_lock);
}
void authTestPeerPassword(tunnel_t *t)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    rwlockWriteLock(&ts->state_lock);
    require(usersChangePassword(&ts->store.users, usersLookupByIdentifier(&ts->store.users, 42), "changed"),
            "password update failed");
    authenticationserverBumpConfigRevision(t);
    rwlockWriteUnlock(&ts->state_lock);
}
void authTestPeerPopulate(tunnel_t *t, unsigned count)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    for (unsigned i = 0; i < count; ++i)
    {
        char password[64];
        snprintf(password, sizeof(password), "account-%u", i);
        user_t user;
        require(userCreate(&user, password), "peer user construction failed");
        userSetId(&user, i + 42);
        if (usersLookupByIdentifier(&ts->store.users, i + 42) == NULL)
            require(usersAddUser(&ts->store.users, &user), "peer user insertion failed");
        userDestroy(&user);
    }
}
void authTestPeerRemoveUser(tunnel_t *t)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    require(usersRemoveUserByIdentifier(&ts->store.users, 42), "peer user removal failed");
}
uint64_t authTestPeerSequence(tunnel_t *t, unsigned client)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    return ts->auth_clients[client].last_sequence;
}
void authTestPeerCredentials(tunnel_t *t, unsigned client, uint8_t token[64], char epoch[65])
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    for (uint32_t i = 0; i < ts->sessions_count; ++i)
        if (ts->sessions[i]->accounting_client == &ts->auth_clients[client])
        {
            memoryCopy(token, ts->sessions[i]->token, 64);
            memoryCopy(epoch, ts->sessions[i]->accounting_epoch, 64);
            epoch[64] = 0;
            return;
        }
    require(false, "peer session unavailable");
}

size_t authTestPeerPadUsersResponse(tunnel_t *t, size_t json_length)
{
    authenticationserver_tstate_t *ts   = tunnelGetState(t);
    user_t                        *user = usersLookupByIdentifier(&ts->store.users, 42);
    /* Keep the optional notes property present while measuring fixed overhead. */
    require(usersSetUserNotes(&ts->store.users, user, "a"), "seed notes failed");
    cJSON *json = usersToJson(&ts->store.users);
    require(json != NULL, "peer users export failed");
    discard jsonAddUint64ToObject(json, "server-time-ms", getTimeOfDayMS());
    discard jsonAddUint64ToObject(json, "accounting-time-ms", authenticationserverAccountingTimeMS(ts));
    char   *text = authenticationserverSerializeResponseJson(json);
    require(text != NULL && stringLength(text) < json_length, "target JSON is too small");
    const size_t padding = json_length - stringLength(text) + 1;
    cJSON_free(text);
    cJSON_Delete(json);
    char *notes = memoryAllocate(padding + 1);
    memset(notes, 'a', padding);
    notes[padding] = '\0';
    require(usersSetUserNotes(&ts->store.users, user, notes), "padded notes failed");
    memoryFree(notes);
    return padding;
}

void authTestPeerPermissions(tunnel_t *t, unsigned client, bool user_write, bool stats_push)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    rwlockWriteLock(&ts->state_lock);
    ts->auth_clients[client].allow_user_write = user_write;
    ts->auth_clients[client].allow_stats_push = stats_push;
    for (uint32_t i = 0; i < ts->sessions_count; ++i)
        if (ts->sessions[i]->accounting_client == &ts->auth_clients[client])
        {
            ts->sessions[i]->allow_user_write = user_write;
            ts->sessions[i]->allow_stats_push = stats_push;
        }
    rwlockWriteUnlock(&ts->state_lock);
}

void authTestPeerSetUser(tunnel_t *t, uint64_t id, const user_update_t *update)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    rwlockWriteLock(&ts->state_lock);
    require(usersUpdateUser(&ts->store.users, usersLookupByIdentifier(&ts->store.users, id), update),
            "peer user setup failed");
    rwlockWriteUnlock(&ts->state_lock);
}

cJSON *authTestPeerUserJson(tunnel_t *t, uint64_t id)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    rwlockReadLock(&ts->state_lock);
    cJSON *json = usersUserToJsonByIdentifier(&ts->store.users, id);
    rwlockReadUnlock(&ts->state_lock);
    require(json != NULL, "peer user export failed");
    return json;
}

char *authTestPeerSnapshot(tunnel_t *t)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    rwlockReadLock(&ts->state_lock);
    require(usersValidate(&ts->store.users), "peer indexes invalid");
    cJSON  *json = usersToJson(&ts->store.users);
    discard jsonAddUint64ToObject(json, "config-revision", ts->store.config_revision);
    discard jsonAddUint64ToObject(json, "stats-revision", ts->store.stats_revision);
    cJSON  *checkpoints = cJSON_AddArrayToObject(json, "checkpoints");
    for (uint32_t i = 0; i < ts->auth_clients_count; ++i)
    {
        const authenticationserver_auth_client_t *client    = &ts->auth_clients[i];
        char                                      epoch[65] = {0}, digest[65] = {0};
        memoryCopy(epoch, client->accounting_epoch, 64);
        asciiHexEncodeBytesLower(client->last_digest, sizeof(client->last_digest), (uint8_t *) digest);
        cJSON  *checkpoint = cJSON_CreateObject();
        discard cJSON_AddItemToArray(checkpoints, checkpoint);
        discard cJSON_AddStringToObject(checkpoint, "epoch", epoch);
        discard cJSON_AddStringToObject(checkpoint, "digest", digest);
        discard jsonAddUint64ToObject(checkpoint, "sequence", client->last_sequence);
    }
    char *text = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    rwlockReadUnlock(&ts->state_lock);
    return text;
}

void authTestPeerInsertUser(tunnel_t *t, uint64_t id, const char *password)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    user_t                         user;
    require(userCreate(&user, password), "peer insert construction failed");
    userSetId(&user, id);
    rwlockWriteLock(&ts->state_lock);
    require(usersAddUser(&ts->store.users, &user), "peer insert failed");
    rwlockWriteUnlock(&ts->state_lock);
    userDestroy(&user);
}

cJSON *authTestPeerApi(tunnel_t *t, const char *operation, const char *body, enum api_result_e expected)
{
    if (! nodeApiHasRegistration(t))
        require(authenticationserverRegisterApi(t), "peer API registration failed");
    const node_api_operation_t *descriptor = nodeApiFind(t, operation);
    require(descriptor != NULL && descriptor->execution == kNodeApiCallingWorker &&
                descriptor->read_only ==
                    (strcmp(operation, "update-user") != 0 && strcmp(operation, "create-user") != 0 &&
                     strcmp(operation, "change-user-password") != 0),
            "peer API descriptor contract");
    const size_t length  = strlen(body);
    sbuf_t      *request = bufferpoolGetBestFit(getCurrentEventWorkerBufferPool(), (uint32_t) length, 0);
    sbufSetLength(request, (uint32_t) length);
    memoryCopy(sbufGetMutablePtr(request), body, length);
    node_api_call_context_t context = {.operation                = operation,
                                       .principal                = "sync-fixture",
                                       .max_response_body_size   = 4096,
                                       .working_memory_allowance = 1024 * 1024};
    api_result_t            result  = descriptor->handler(t, request, &context);
    require(result.result_code == expected && result.buffer != NULL, "peer API result contract");
    cJSON *json = cJSON_ParseWithLength((const char *) sbufGetRawPtr(result.buffer), sbufGetLength(result.buffer));
    bufferpoolReuseBuffer(getCurrentEventWorkerBufferPool(), result.buffer);
    require(cJSON_IsObject(json), "peer API did not return JSON");
    return json;
}

void authTestPeerSetConfigRevision(tunnel_t *t, uint64_t revision)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    rwlockWriteLock(&ts->state_lock);
    ts->store.config_revision = revision;
    rwlockWriteUnlock(&ts->state_lock);
}
