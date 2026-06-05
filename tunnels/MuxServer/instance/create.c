#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *muxserverTunnelCreate(node_t *node)
{
    int wc = getWorkersCount();

    tunnel_t *t = tunnelCreate(node, sizeof(muxserver_tstate_t) + (wc * sizeof(line_t *)), sizeof(muxserver_lstate_t));

    t->fnInitU    = &muxserverTunnelUpStreamInit;
    t->fnEstU     = &muxserverTunnelUpStreamEst;
    t->fnFinU     = &muxserverTunnelUpStreamFinish;
    t->fnPayloadU = &muxserverTunnelUpStreamPayload;
    t->fnPauseU   = &muxserverTunnelUpStreamPause;
    t->fnResumeU  = &muxserverTunnelUpStreamResume;

    t->fnInitD    = &muxserverTunnelDownStreamInit;
    t->fnEstD     = &muxserverTunnelDownStreamEst;
    t->fnFinD     = &muxserverTunnelDownStreamFinish;
    t->fnPayloadD = &muxserverTunnelDownStreamPayload;
    t->fnPauseD   = &muxserverTunnelDownStreamPause;
    t->fnResumeD  = &muxserverTunnelDownStreamResume;

    t->onPrepare = &muxserverTunnelOnPrepair;
    t->onStart   = &muxserverTunnelOnStart;
    t->onDestroy = &muxserverTunnelDestroy;

    const cJSON        *settings = node->node_settings_json;
    muxserver_tstate_t *ts       = tunnelGetState(t);
    int                 child_buffer_limit = kMuxDefaultChildBufferLimit;
    int                 child_buffer_pause_tolerance = kMuxDefaultChildBufferPauseTolerance;
    bool                log_main_line_stats = false;

    if (cJSON_IsObject(settings))
    {
        getIntFromJsonObjectOrDefault(&child_buffer_limit, settings, "child-buffer-limit",
                                      kMuxDefaultChildBufferLimit);
        getIntFromJsonObjectOrDefault(&child_buffer_pause_tolerance, settings, "child-buffer-pause-tolerance",
                                      kMuxDefaultChildBufferPauseTolerance);
        getBoolFromJsonObjectOrDefault(&log_main_line_stats, settings, "log-main-line-stats", false);
    }
    if (child_buffer_limit <= 0)
    {
        LOGF("MuxServer: \"child-buffer-limit\" must be greater than 0, got %d", child_buffer_limit);
        tunnelDestroy(t);
        return NULL;
    }
    if (child_buffer_pause_tolerance < 0)
    {
        LOGF("MuxServer: \"child-buffer-pause-tolerance\" must be greater than or equal to 0, got %d",
             child_buffer_pause_tolerance);
        tunnelDestroy(t);
        return NULL;
    }
    ts->child_buffer_limit = (uint32_t) child_buffer_limit;
    ts->child_buffer_pause_tolerance =
        (uint32_t) min((size_t) child_buffer_pause_tolerance, (size_t) child_buffer_limit);
    ts->log_main_line_stats = log_main_line_stats;

    return t;
}
