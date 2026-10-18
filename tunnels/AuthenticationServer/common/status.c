#include "structure.h"

static bool authenticationserverStatusDeadlineExpired(uint64_t deadline_ms)
{
    return deadline_ms != 0 && getHRTimeUs() / 1000U >= deadline_ms;
}

authenticationserver_status_result_t authenticationserverStatusSnapshot(tunnel_t *t, uint64_t deadline_ms,
                                                                        authenticationserver_status_t *out)
{
    assert(t != NULL && out != NULL);
    *out = (authenticationserver_status_t) {0};
    if (authenticationserverStatusDeadlineExpired(deadline_ms))
        return kAuthenticationServerStatusTimeout;

    authenticationserver_tstate_t *ts = tunnelGetState(t);
    if (! rwlockTryReadLock(&ts->state_lock))
        return kAuthenticationServerStatusBusy;

    size_t                     user_count = 0;
    const user_public_result_t counted    = usersTryCount(&ts->store.users, deadline_ms, &user_count);
    if (counted != kUserPublicOk)
    {
        rwlockReadUnlock(&ts->state_lock);
        return counted == kUserPublicTimeout ? kAuthenticationServerStatusTimeout : kAuthenticationServerStatusBusy;
    }

    const uint64_t                now     = getHRTimeUs() / 1000U;
    authenticationserver_status_t sampled = {
        .database_loaded                 = ts->database_loaded,
        .user_count                      = user_count,
        .configured_producer_count       = ts->auth_clients_count,
        .session_record_count            = ts->sessions_count,
        .config_revision                 = ts->store.config_revision,
        .stats_revision                  = ts->store.stats_revision,
        .primary_save_last_result        = ts->primary_save_last_result,
        .primary_save_last_attempt_valid = ts->primary_save_last_attempt_valid,
        .primary_save_last_success_valid = ts->primary_save_last_success_valid,
        .primary_save_last_attempt_age_ms =
            now >= ts->primary_save_last_attempt_ms ? now - ts->primary_save_last_attempt_ms : 0,
        .primary_save_last_success_age_ms =
            now >= ts->primary_save_last_success_ms ? now - ts->primary_save_last_success_ms : 0,
    };
    memoryCopy(sampled.instance_id, ts->api_instance_id, sizeof(sampled.instance_id));
    rwlockReadUnlock(&ts->state_lock);
    if (authenticationserverStatusDeadlineExpired(deadline_ms))
        return kAuthenticationServerStatusTimeout;
    *out = sampled;
    return kAuthenticationServerStatusOk;
}
