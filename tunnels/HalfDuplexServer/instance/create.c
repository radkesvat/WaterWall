#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *halfduplexserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(halfduplexserver_tstate_t), sizeof(halfduplexserver_lstate_t));
    if (! t)
    {
        return NULL;
    }

    halfduplexserver_tstate_t *ts = tunnelGetState(t);

    t->fnInitU    = &halfduplexserverTunnelUpStreamInit;
    t->fnEstU     = &halfduplexserverTunnelUpStreamEst;
    t->fnFinU     = &halfduplexserverTunnelUpStreamFinish;
    t->fnPayloadU = &halfduplexserverTunnelUpStreamPayload;
    t->fnPauseU   = &halfduplexserverTunnelUpStreamPause;
    t->fnResumeU  = &halfduplexserverTunnelUpStreamResume;

    t->fnInitD    = &halfduplexserverTunnelDownStreamInit;
    t->fnEstD     = &halfduplexserverTunnelDownStreamEst;
    t->fnFinD     = &halfduplexserverTunnelDownStreamFinish;
    t->fnPayloadD = &halfduplexserverTunnelDownStreamPayload;
    t->fnPauseD   = &halfduplexserverTunnelDownStreamPause;
    t->fnResumeD  = &halfduplexserverTunnelDownStreamResume;

    t->onPrepare = &halfduplexserverTunnelOnPrepair;
    t->onStart   = &halfduplexserverTunnelOnStart;
    t->onStop    = &halfduplexserverTunnelOnStop;
    t->onDestroy = &halfduplexserverTunnelDestroy;

    ts->upload_line_map   = hmap_cons_t_init();
    ts->download_line_map = hmap_cons_t_init();

    if (UNLIKELY(! mutexTryInit(&ts->upload_line_map_mutex)))
    {
        halfduplexserverTunnelDestroy(t);
        return NULL;
    }
    ts->upload_line_map_mutex_initialized = true;

    if (UNLIKELY(! mutexTryInit(&ts->download_line_map_mutex)))
    {
        halfduplexserverTunnelDestroy(t);
        return NULL;
    }
    ts->download_line_map_mutex_initialized = true;

    if (UNLIKELY(! hmap_cons_t_reserve(&ts->download_line_map, kHmapCap) ||
                 hmap_cons_t_capacity(&ts->download_line_map) < kHmapCap ||
                 ! hmap_cons_t_reserve(&ts->upload_line_map, kHmapCap) ||
                 hmap_cons_t_capacity(&ts->upload_line_map) < kHmapCap))
    {
        halfduplexserverTunnelDestroy(t);
        return NULL;
    }

    tunnel_t *pipe_tunnel = pipetunnelCreate(t);
    if (! pipe_tunnel)
    {
        // The wrapper never took ownership, so the child is still this call's.
        halfduplexserverTunnelDestroy(t);
        return NULL;
    }

    return pipe_tunnel;
}
