#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelDestroy(tunnel_t *t)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);

    if (ts->save_timer != NULL)
    {
        weventSetUserData(ts->save_timer, NULL);
        wtimerDelete(ts->save_timer);
        ts->save_timer = NULL;
    }

    if (ts->users_created)
    {
        if (ts->database_loaded && ! authenticationserverSaveDatabase(ts))
        {
            LOGW("AuthenticationServer: final users database save failed during destroy");
        }
        usersDestroy(&ts->users);
        ts->users_created = false;
        ts->database_loaded = false;
    }

    memoryFree(ts->db_path);
    memoryFree(ts->backup_path);

    tunnelDestroy(t);
}
