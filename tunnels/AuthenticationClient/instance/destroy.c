#include "api/node_api.h"
#include "structure.h"

#include "loggers/network_logger.h"

static void authenticationclientDestroyUsersSnapshot(users_t *users)
{
    if (UNLIKELY(users == NULL))
    {
        return;
    }

    usersDestroy(users);
    memoryFreeAligned(users);
}

void authenticationclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                        context;
    authenticationclient_tstate_t *ts = tunnelGetState(t);

    nodeApiUnregister(t);

    memoryFree(ts->pending_requests);
    cJSON_free(ts->pending_batch);
    memoryFree(ts->pending_entries);
    memoryFree(ts->catchup_entries);
    ts->pending_requests = NULL;

    rwlockWriteLock(&ts->users_lock);
    users_t *users               = ts->users;
    users_t *sync_baseline_users = ts->sync_baseline_users;
    ts->users                    = NULL;
    ts->sync_baseline_users      = NULL;
    rwlockWriteUnlock(&ts->users_lock);

    if (LIKELY(users != NULL))
    {
        usersDestroy(users);
        memoryFreeAligned(users);
    }
    authenticationclientDestroyUsersSnapshot(sync_baseline_users);
    rwlockDestroy(&ts->users_lock);

    assert(ts->bandwidth_ticket_count == 0);
    assert(ts->bandwidth_queued_cost.bytes == 0 && ts->bandwidth_queued_cost.charge == 0 &&
           ts->bandwidth_queued_cost.entries == 0);
    memoryFree(ts->bandwidth_tickets);
    mutexDestroy(&ts->control_mutex);

    memoryFree(ts->name);
    memoryFree(ts->secret);
    memoryZero(ts->token, sizeof(ts->token));

    tunnelDestroy(t);
}
