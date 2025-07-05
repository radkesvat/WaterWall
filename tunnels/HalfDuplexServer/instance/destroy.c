#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexserverTunnelDestroy(tunnel_t *t)
{
    halfduplexserver_tstate_t *ts = tunnelGetState(t);

    mutexDestroy(&ts->download_line_map_mutex);
    mutexDestroy(&ts->upload_line_map_mutex);
    c_foreach(k, hmap_cons_t, ts->download_line_map)
    {
        halfduplexserver_lstate_t *ls = k.ref->second;
        discard ls;
        assert(ls->buffering == NULL);
    }
    c_foreach(k, hmap_cons_t, ts->upload_line_map)
    {
        halfduplexserver_lstate_t *ls = k.ref->second;
        if (ls->buffering)
        {
            LOGD("houeou");
            sbufDestroy(ls->buffering);
        }
    }
    hmap_cons_t_drop(&ts->download_line_map);

    hmap_cons_t_drop(&ts->upload_line_map);
    tunnelDestroy(t);
}
