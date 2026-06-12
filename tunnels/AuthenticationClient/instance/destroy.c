#include "structure.h"

#include "loggers/network_logger.h"

static void authenticationclientDestroyUsersSnapshot(users_t *users)
{
    if (users == NULL)
    {
        return;
    }

    usersDestroy(users);
    memoryFree(users);
}

void authenticationclientTunnelDestroy(tunnel_t *t)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);

    memoryFree(ts->pending_requests);
    ts->pending_requests = NULL;

    rwlockWriteLock(&ts->users_lock);
    users_t *users               = ts->users;
    users_t *sync_baseline_users = ts->sync_baseline_users;
    users_t *pending_push_users  = ts->pending_push_users;
    ts->users                    = NULL;
    ts->sync_baseline_users      = NULL;
    ts->pending_push_users       = NULL;
    rwlockWriteUnlock(&ts->users_lock);

    if (users != NULL)
    {
        usersDestroy(users);
        memoryFree(users);
    }
    authenticationclientDestroyUsersSnapshot(sync_baseline_users);
    authenticationclientDestroyUsersSnapshot(pending_push_users);
    rwlockDestroy(&ts->users_lock);

    mutexDestroy(&ts->control_mutex);

    memoryFree(ts->name);
    memoryFree(ts->secret);
    wCryptoZero(ts->token, sizeof(ts->token));

    tunnelDestroy(t);
}
