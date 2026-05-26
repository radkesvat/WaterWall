#include "structure.h"

#include "loggers/network_logger.h"

uint32_t authenticationserverGetServerIndex(tunnel_t *t)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    return (uint32_t) atomicLoadRelaxed(&ts->server_index);
}

bool authenticationserverMarkUserDirtyBySHA256(tunnel_t *t, const uint8_t sha256[SHA256_DIGEST_SIZE])
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);

    users_update_result_t result = usersIncrementSyncIndexBySHA256(&ts->users, sha256, NULL);
    if (result != kUsersUpdateResultOk)
    {
        LOGW("AuthenticationServer: failed to mark changed user as dirty");
        return false;
    }

    atomicAdd(&ts->server_index, 1U);
    return true;
}

users_update_result_t authenticationserverUpdateUserBySHA256AndMarkDirty(tunnel_t *t,
                                                                         const uint8_t sha256[SHA256_DIGEST_SIZE],
                                                                         const user_update_t *update)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);

    /*
     * The user update and per-user sync bump must be one users_t write-locked
     * operation. Otherwise PullChangesSync can observe changed user data before
     * the dirty index changes, or the reverse.
     */
    users_update_result_t result = usersUpdateUserBySHA256AndIncrementSync(&ts->users, sha256, update, NULL);
    if (result == kUsersUpdateResultOk)
    {
        atomicAdd(&ts->server_index, 1U);
    }

    return result;
}
