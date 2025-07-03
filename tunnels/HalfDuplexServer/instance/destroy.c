#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexserverTunnelDestroy(tunnel_t *t)
{
    halfduplexserver_tstate_t* ts = tunnelGetState(t);

    mutexDestroy(&ts->download_line_map_mutex);
    mutexDestroy(&ts->upload_line_map_mutex);
    hmap_cons_t_drop(&ts->download_line_map);
    hmap_cons_t_drop(&ts->upload_line_map);
    tunnelDestroy(t);
}

