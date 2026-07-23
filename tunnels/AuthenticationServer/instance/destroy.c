#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelDestroy(tunnel_t *t)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);

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
