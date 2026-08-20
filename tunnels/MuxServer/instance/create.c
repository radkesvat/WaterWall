#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *muxserverTunnelCreate(node_t *node)
{
    int wc = getWorkersCount();

    size_t registry_bytes;
    if (wc <= 0 || ! memoryTryComputeArraySize((size_t) wc, sizeof(muxserver_detached_registry_t), &registry_bytes) ||
        registry_bytes > SIZE_MAX - sizeof(muxserver_tstate_t))
    {
        LOGF("MuxServer: detached registry geometry is not representable");
        return NULL;
    }

    tunnel_t *t = tunnelCreate(node, sizeof(muxserver_tstate_t) + registry_bytes, sizeof(muxserver_lstate_t));
    if (! t)
    {
        return NULL;
    }

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

    t->onPrepare    = &muxserverTunnelOnPrepair;
    t->onStart      = &muxserverTunnelOnStart;
    t->onWorkerStop = &muxserverTunnelOnWorkerStop;
    t->onStop       = &muxserverTunnelOnStop;
    t->onDestroy    = &muxserverTunnelDestroy;

    const mux_detached_defaults_t detached_defaults             = muxGetDefaultDetachedLimits(RAM_PROFILE);
    const cJSON                  *settings                      = node->node_settings_json;
    muxserver_tstate_t           *ts                            = tunnelGetState(t);
    int                           child_buffer_limit            = kMuxDefaultChildBufferLimit;
    int                           child_buffer_pause_tolerance  = kMuxDefaultChildBufferPauseTolerance;
    int                           child_buffer_resume_threshold = kMuxDefaultChildBufferResumeThreshold;
    int                           parent_buffer_limit           = kMuxDefaultParentBufferLimit;
    int                           detached_buffer_limit         = (int) detached_defaults.buffer_limit;
    int                           detached_child_limit          = (int) detached_defaults.child_limit;
    bool                          log_main_line_stats           = false;

    if (cJSON_IsObject(settings))
    {
        getIntFromJsonObjectOrDefault(&child_buffer_limit, settings, "child-buffer-limit", kMuxDefaultChildBufferLimit);
        getIntFromJsonObjectOrDefault(&child_buffer_pause_tolerance,
                                      settings,
                                      "child-buffer-pause-tolerance",
                                      kMuxDefaultChildBufferPauseTolerance);
        getIntFromJsonObjectOrDefault(&child_buffer_resume_threshold,
                                      settings,
                                      "child-buffer-resume-threshold",
                                      kMuxDefaultChildBufferResumeThreshold);
        getIntFromJsonObjectOrDefault(
            &parent_buffer_limit, settings, "parent-buffer-limit", kMuxDefaultParentBufferLimit);
        getIntFromJsonObjectOrDefault(
            &detached_buffer_limit, settings, "detached-buffer-limit", (int) detached_defaults.buffer_limit);
        getIntFromJsonObjectOrDefault(
            &detached_child_limit, settings, "detached-child-limit", (int) detached_defaults.child_limit);
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
    if (child_buffer_resume_threshold <= 0)
    {
        LOGF("MuxServer: \"child-buffer-resume-threshold\" must be greater than 0, got %d",
             child_buffer_resume_threshold);
        tunnelDestroy(t);
        return NULL;
    }
    if (parent_buffer_limit < 0)
    {
        LOGF("MuxServer: \"parent-buffer-limit\" must be greater than or equal to 0, got %d", parent_buffer_limit);
        tunnelDestroy(t);
        return NULL;
    }
    if (detached_buffer_limit < 0)
    {
        LOGF("MuxServer: \"detached-buffer-limit\" must be greater than or equal to 0, got %d", detached_buffer_limit);
        tunnelDestroy(t);
        return NULL;
    }
    if (detached_child_limit < 0)
    {
        LOGF("MuxServer: \"detached-child-limit\" must be greater than or equal to 0, got %d", detached_child_limit);
        tunnelDestroy(t);
        return NULL;
    }
    ts->child_buffer_limit = (uint32_t) child_buffer_limit;
    ts->child_buffer_pause_tolerance =
        (uint32_t) min((size_t) child_buffer_pause_tolerance, (size_t) child_buffer_limit);
    ts->child_buffer_resume_threshold =
        (uint32_t) min((size_t) child_buffer_resume_threshold, (size_t) child_buffer_limit);
    // This is a per-parent budget, not another per-child limit, so it may
    // intentionally be smaller than child_buffer_limit. Zero disables it.
    ts->parent_buffer_limit   = (uint32_t) parent_buffer_limit;
    ts->detached_buffer_limit = (uint32_t) detached_buffer_limit;
    ts->detached_child_limit  = (uint32_t) detached_child_limit;
    ts->workers_count         = (uint32_t) wc;
    ts->log_main_line_stats   = log_main_line_stats;

    return t;
}
