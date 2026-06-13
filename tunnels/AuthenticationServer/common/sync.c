#include "structure.h"

void authenticationserverGetRevisions(tunnel_t *t, uint64_t *config_revision, uint64_t *stats_revision)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);

    recursivemutexLock(&ts->database_mutex);
    if (LIKELY(config_revision != NULL))
    {
        *config_revision = ts->store.config_revision;
    }
    if (LIKELY(stats_revision != NULL))
    {
        *stats_revision = ts->store.stats_revision;
    }
    recursivemutexUnlock(&ts->database_mutex);
}

void authenticationserverBumpConfigRevision(tunnel_t *t)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);

    ts->store.config_revision += 1U;
}

void authenticationserverBumpStatsRevision(tunnel_t *t)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);

    ts->store.stats_revision += 1U;
}

users_update_result_t authenticationserverUpdateUserBySHA256AndBumpConfigRevision(
    tunnel_t *t, const uint8_t sha256[SHA256_DIGEST_SIZE], const user_update_t *update)
{
    authenticationserver_tstate_t *ts     = tunnelGetState(t);
    users_update_result_t          result = usersUpdateUserBySHA256(&ts->store.users, sha256, update);

    if (LIKELY(result == kUsersUpdateResultOk))
    {
        authenticationserverBumpConfigRevision(t);
    }

    return result;
}
