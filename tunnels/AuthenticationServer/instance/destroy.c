#include "api/node_api.h"
#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                        context;
    authenticationserver_tstate_t *ts = tunnelGetState(t);

    nodeApiUnregister(t);

    /* NodeManager has settled producers and registered API jobs before destroy.
     * The writer owns only copied records and must join before logger teardown. */
    authenticationserverAuditDestroy(ts->audit);
    ts->audit = NULL;

    if (UNLIKELY(ts->database_loaded && ! authenticationserverSaveDatabase(ts)))
    {
        LOGW("AuthenticationServer: final users database save failed during destroy");
    }
    usersDestroy(&ts->store.users);
    ts->database_loaded = false;

    authenticationserverSessionsDestroy(ts);
    authenticationserverAuthClientsDestroy(ts);

    memoryFree(ts->db_path);
    memoryFree(ts->backup_path);
    memoryFree(ts->normal_backups_path);

    rwlockDestroy(&ts->state_lock);

    tunnelDestroy(t);
}
