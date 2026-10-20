#include "loggers/network_logger.h"
#include "structure.h"

void authenticationserverInitializeAccountingClock(authenticationserver_tstate_t *ts)
{
    ts->accounting_anchor_ms    = max(getTimeOfDayMS(), UINT64_C(1));
    ts->accounting_monotonic_ms = getHRTimeUs() / 1000ULL;
}

uint64_t authenticationserverAccountingTimeMS(const authenticationserver_tstate_t *ts)
{
    assert(ts->accounting_anchor_ms != 0);
    const uint64_t now     = getHRTimeUs() / 1000ULL;
    const uint64_t elapsed = now > ts->accounting_monotonic_ms ? now - ts->accounting_monotonic_ms : 0;
    return elapsed > UINT64_MAX - ts->accounting_anchor_ms ? UINT64_MAX : ts->accounting_anchor_ms + elapsed;
}

void authenticationserverGetRevisions(tunnel_t *t, uint64_t *config_revision, uint64_t *stats_revision)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);

    rwlockReadLock(&ts->state_lock);
    if (LIKELY(config_revision != NULL))
    {
        *config_revision = ts->store.config_revision;
    }
    if (LIKELY(stats_revision != NULL))
    {
        *stats_revision = ts->store.stats_revision;
    }
    rwlockReadUnlock(&ts->state_lock);
}

void authenticationserverBumpConfigRevision(tunnel_t *t)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);

    if (ts->store.config_revision == UINT64_MAX)
    {
        LOGF("AuthenticationServer: configuration revision exhausted without preflight");
        abortProgramNow(1);
    }
    ts->store.config_revision += 1U;
    ts->database_dirty = true;
}

void authenticationserverBumpStatsRevision(tunnel_t *t)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);

    ts->store.stats_revision += 1U;
    ts->database_dirty = true;
}

bool authenticationserverUserHasRequiredId(const user_t *user)
{
    return user != NULL && userGetId((user_t *) user) != 0;
}

users_update_result_t authenticationserverPatchConfigAndBumpRevision(tunnel_t *t, uint64_t id,
                                                                     const user_config_patch_t *patch)
{
    authenticationserver_tstate_t *ts     = tunnelGetState(t);
    if (ts->store.config_revision == UINT64_MAX)
        return kUsersUpdateResultRevisionExhausted;
    users_update_result_t          result = usersPatchConfigByIdentifier(&ts->store.users, id, patch);

    if (LIKELY(result == kUsersUpdateResultOk))
    {
        authenticationserverBumpConfigRevision(t);
    }

    return result;
}
