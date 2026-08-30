#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                    context;
    halfduplexserver_tstate_t *ts = tunnelGetState(t);

    const size_t pending_uploads   = hmap_cons_t_size(&ts->upload_line_map);
    const size_t pending_downloads = hmap_cons_t_size(&ts->download_line_map);
    assert(pending_uploads == 0 && pending_downloads == 0);
    if (UNLIKELY(pending_uploads != 0 || pending_downloads != 0))
    {
        LOGF("HalfDuplexServer: destroyed with %zu pending upload(s) and %zu pending download(s)",
             pending_uploads,
             pending_downloads);
        abortProgramNow(1);
    }

    hmap_cons_t_drop(&ts->download_line_map);
    hmap_cons_t_drop(&ts->upload_line_map);
    if (ts->pending_line_maps_mutex_initialized)
    {
        mutexDestroy(&ts->pending_line_maps_mutex);
        ts->pending_line_maps_mutex_initialized = false;
    }
    tunnelDestroy(t);
}
