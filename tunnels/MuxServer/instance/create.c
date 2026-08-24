#include "structure.h"

#include "loggers/network_logger.h"

static bool muxserverReadUintSetting(const cJSON *settings, const char *name, uint32_t default_value, int64_t minimum,
                                     int64_t maximum, uint32_t *value)
{
    int64_t parsed = 0;
    switch (jsonGetObjectIntegerInRange(settings, name, minimum, maximum, &parsed))
    {
    case kJsonValueMissing:
        *value = default_value;
        return true;
    case kJsonValuePresent:
        *value = (uint32_t) parsed;
        return true;
    case kJsonValueInvalid:
        LOGF("MuxServer: \"%s\" must be an integer in range [%lld, %lld]",
             name,
             (long long) minimum,
             (long long) maximum);
        return false;
    }
    return false;
}

tunnel_t *muxserverTunnelCreate(node_t *node)
{
    int wc = getWorkersCount();

    size_t worker_state_bytes;
    if (wc <= 0 || ! memoryTryComputeArraySize((size_t) wc, sizeof(muxserver_worker_state_t), &worker_state_bytes) ||
        worker_state_bytes > SIZE_MAX - sizeof(muxserver_tstate_t))
    {
        LOGF("MuxServer: worker-state geometry is not representable");
        return NULL;
    }

    tunnel_t *t = tunnelCreate(node, sizeof(muxserver_tstate_t) + worker_state_bytes, sizeof(muxserver_lstate_t));
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

    t->onPrepare       = &muxserverTunnelOnPrepair;
    t->onStart         = &muxserverTunnelOnStart;
    t->onWorkerQuiesce = &muxserverTunnelOnWorkerQuiesce;
    t->onWorkerStop    = &muxserverTunnelOnWorkerStop;
    t->onStop          = &muxserverTunnelOnStop;
    t->onDestroy       = &muxserverTunnelDestroy;

    const mux_detached_defaults_t  detached_defaults             = muxGetDefaultDetachedLimits(RAM_PROFILE);
    const mux_admission_defaults_t admission_defaults            = muxGetDefaultAdmissionLimits(RAM_PROFILE);
    const cJSON                   *settings                      = node->node_settings_json;
    muxserver_tstate_t            *ts                            = tunnelGetState(t);
    int                            child_buffer_limit            = kMuxDefaultChildBufferLimit;
    int                            child_buffer_pause_tolerance  = kMuxDefaultChildBufferPauseTolerance;
    int                            child_buffer_resume_threshold = kMuxDefaultChildBufferResumeThreshold;
    int                            parent_buffer_limit           = kMuxDefaultParentBufferLimit;
    int                            detached_buffer_limit         = (int) detached_defaults.buffer_limit;
    int                            detached_child_limit          = (int) detached_defaults.child_limit;
    bool                           log_main_line_stats           = false;
    uint32_t                       max_children                  = 0;
    uint32_t                       max_live_children             = 0;
    uint32_t                       memory_fallback_children      = 0;
    uint32_t                       initial_child_idle_timeout_ms = 0;
    uint32_t                       active_child_idle_timeout_ms  = 0;
    uint32_t                       memory_high_watermark         = 0;
    uint32_t                       memory_low_watermark          = 0;
    uint32_t                       memory_reserve                = 0;

    if (! muxserverReadUintSetting(
            settings, "max-children", kMuxDefaultMaxChildrenPerParent, 1, INT_MAX, &max_children) ||
        ! muxserverReadUintSetting(
            settings, "max-live-children", kMuxDefaultMaxLiveChildren, 1, INT_MAX, &max_live_children) ||
        ! muxserverReadUintSetting(settings,
                                   "memory-fallback-max-live-children",
                                   admission_defaults.fallback_live_children,
                                   1,
                                   INT_MAX,
                                   &memory_fallback_children) ||
        ! muxserverReadUintSetting(settings,
                                   "initial-child-idle-timeout-ms",
                                   kMuxDefaultInitialChildIdleTimeoutMs,
                                   1,
                                   INT_MAX,
                                   &initial_child_idle_timeout_ms) ||
        ! muxserverReadUintSetting(settings,
                                   "active-child-idle-timeout-ms",
                                   kMuxDefaultActiveChildIdleTimeoutMs,
                                   1,
                                   INT_MAX,
                                   &active_child_idle_timeout_ms) ||
        ! muxserverReadUintSetting(settings,
                                   "memory-high-watermark-percent",
                                   kMuxDefaultMemoryHighWatermarkPercent,
                                   1,
                                   99,
                                   &memory_high_watermark) ||
        ! muxserverReadUintSetting(settings,
                                   "memory-low-watermark-percent",
                                   kMuxDefaultMemoryLowWatermarkPercent,
                                   1,
                                   99,
                                   &memory_low_watermark) ||
        ! muxserverReadUintSetting(
            settings, "memory-reserve", admission_defaults.memory_reserve, 0, INT_MAX, &memory_reserve))
    {
        tunnelDestroy(t);
        return NULL;
    }

    if (max_children > max_live_children)
    {
        LOGF("MuxServer: \"max-children\" (%u) must not exceed \"max-live-children\" (%u)",
             max_children,
             max_live_children);
        tunnelDestroy(t);
        return NULL;
    }
    if (memory_fallback_children > max_live_children)
    {
        LOGF("MuxServer: \"memory-fallback-max-live-children\" (%u) must not exceed "
             "\"max-live-children\" (%u)",
             memory_fallback_children,
             max_live_children);
        tunnelDestroy(t);
        return NULL;
    }
    if (memory_low_watermark >= memory_high_watermark)
    {
        LOGF("MuxServer: memory low watermark (%u) must be lower than high watermark (%u)",
             memory_low_watermark,
             memory_high_watermark);
        tunnelDestroy(t);
        return NULL;
    }
    if (active_child_idle_timeout_ms < initial_child_idle_timeout_ms)
    {
        LOGF("MuxServer: active child idle timeout (%u) must be at least the initial timeout (%u)",
             active_child_idle_timeout_ms,
             initial_child_idle_timeout_ms);
        tunnelDestroy(t);
        return NULL;
    }

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
    ts->parent_buffer_limit               = (uint32_t) parent_buffer_limit;
    ts->detached_buffer_limit             = (uint32_t) detached_buffer_limit;
    ts->detached_child_limit              = (uint32_t) detached_child_limit;
    ts->max_children                      = max_children;
    ts->max_live_children                 = max_live_children;
    ts->memory_fallback_max_live_children = memory_fallback_children;
    ts->initial_child_idle_timeout_ms     = initial_child_idle_timeout_ms;
    ts->active_child_idle_timeout_ms      = active_child_idle_timeout_ms;
    ts->memory_high_watermark_percent     = memory_high_watermark;
    ts->memory_low_watermark_percent      = memory_low_watermark;
    ts->memory_reserve                    = memory_reserve;
    ts->workers_count                     = (uint32_t) wc;
    ts->log_main_line_stats               = log_main_line_stats;

    atomicStoreRelaxed(&ts->live_children_count, 0);
    atomicStoreU64Relaxed(&ts->memory_admission_state, 0);
    atomicLogRateLimiterInitialize(&ts->resource_admission_log_limiter);
    atomicLogRateLimiterInitialize(&ts->protocol_abuse_log_limiter);
    atomicLogRateLimiterInitialize(&ts->memory_transition_log_limiter);
    atomicLogRateLimiterInitialize(&ts->idle_expiry_log_limiter);

    return t;
}
