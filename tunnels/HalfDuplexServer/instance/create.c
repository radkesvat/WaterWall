#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *halfduplexserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(halfduplexserver_tstate_t), sizeof(halfduplexserver_lstate_t));

    
    halfduplexserver_tstate_t* ts = tunnelGetState(t);

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
    t->onDestroy = &halfduplexserverTunnelDestroy;

    mutexInit(&ts->upload_line_map_mutex);
    mutexInit(&ts->download_line_map_mutex);
    ts->download_line_map = hmap_cons_t_with_capacity(kHmapCap);
    ts->upload_line_map   = hmap_cons_t_with_capacity(kHmapCap);

    tunnel_t* pipe_tunnel = pipetunnelCreate(t);
    return pipe_tunnel;
}
