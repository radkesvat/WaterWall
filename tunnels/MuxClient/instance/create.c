#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *muxclientTunnelCreate(node_t *node)
{
    int wc = getWorkersCount();

    tunnel_t *t = tunnelCreate(node, sizeof(muxclient_tstate_t) + (wc * sizeof(line_t *)), sizeof(muxclient_lstate_t));

    t->fnInitU    = &muxclientTunnelUpStreamInit;
    t->fnEstU     = &muxclientTunnelUpStreamEst;
    t->fnFinU     = &muxclientTunnelUpStreamFinish;
    t->fnPayloadU = &muxclientTunnelUpStreamPayload;
    t->fnPauseU   = &muxclientTunnelUpStreamPause;
    t->fnResumeU  = &muxclientTunnelUpStreamResume;

    t->fnInitD    = &muxclientTunnelDownStreamInit;
    t->fnEstD     = &muxclientTunnelDownStreamEst;
    t->fnFinD     = &muxclientTunnelDownStreamFinish;
    t->fnPayloadD = &muxclientTunnelDownStreamPayload;
    t->fnPauseD   = &muxclientTunnelDownStreamPause;
    t->fnResumeD  = &muxclientTunnelDownStreamResume;

    t->onPrepare = &muxclientTunnelOnPrepair;
    t->onStart   = &muxclientTunnelOnStart;
    t->onDestroy = &muxclientTunnelDestroy;

    const cJSON        *settings = node->node_settings_json;
    muxclient_tstate_t *ts       = tunnelGetState(t);
    int                 child_buffer_limit = kMuxDefaultChildBufferLimit;
    int                 child_buffer_pause_tolerance = kMuxDefaultChildBufferPauseTolerance;

    getIntFromJsonObjectOrDefault(&child_buffer_limit, settings, "child-buffer-limit", kMuxDefaultChildBufferLimit);
    getIntFromJsonObjectOrDefault(&child_buffer_pause_tolerance, settings, "child-buffer-pause-tolerance",
                                  kMuxDefaultChildBufferPauseTolerance);
    if (child_buffer_limit <= 0)
    {
        LOGF("MuxClient: \"child-buffer-limit\" must be greater than 0, got %d", child_buffer_limit);
        tunnelDestroy(t);
        return NULL;
    }
    if (child_buffer_pause_tolerance < 0)
    {
        LOGF("MuxClient: \"child-buffer-pause-tolerance\" must be greater than or equal to 0, got %d",
             child_buffer_pause_tolerance);
        tunnelDestroy(t);
        return NULL;
    }
    ts->child_buffer_limit = (uint32_t) child_buffer_limit;
    ts->child_buffer_pause_tolerance =
        (uint32_t) min((size_t) child_buffer_pause_tolerance, (size_t) child_buffer_limit);

    ts->concurrency_mode = parseDynamicNumericValueFromJsonObject(settings, "mode", 3, "timer", "counter",
                                                                  "fixed-connections-count").status;

    if (ts->concurrency_mode != kConcurrencyModeTimer && ts->concurrency_mode != kConcurrencyModeCounter &&
        ts->concurrency_mode != kConcurrencyModeFixedConnectionsCount)
    {
        LOGF("MuxClient: Invalid concurrency mode: %u", ts->concurrency_mode);
        tunnelDestroy(t);
        return NULL;
    }

    if (ts->concurrency_mode == kConcurrencyModeTimer)
    {
        int duration = 0;
        if (! getIntFromJsonObject(&duration, settings, "connection-duration"))
        {
            LOGF("MuxClient: connection-duration is not specified", duration);
            tunnelDestroy(t);
            return NULL;
        }
        if (duration <= 0)
        {
            LOGF("MuxClient: duration must be greater than 0, got %d", duration);
            tunnelDestroy(t);
            return NULL;
        }
        if (duration <= 60)
        {
            LOGF("MuxClient: This value is in Milliseconds: you are probably wrong with value lower than 60 , value is"
                 " %d",
                 duration);
            tunnelDestroy(t);
            return NULL;
        }

        ts->concurrency_duration = duration;
    }

    if (ts->concurrency_mode == kConcurrencyModeCounter)
    {
        int counter = 0;
        if (! getIntFromJsonObject(&counter, settings, "connection-capacity"))
        {
            LOGF("MuxClient: \"connection-capacity\" is not specified", counter);
            tunnelDestroy(t);
            return NULL;
        }

        if (counter <= 0)
        {
            LOGF("MuxClient: \"connection-capacity\" must be greater than 0, got %d", counter);
            tunnelDestroy(t);
            return NULL;
        }
        ts->concurrency_capacity = counter;
    }

    if (ts->concurrency_mode == kConcurrencyModeFixedConnectionsCount)
    {
        int fixed_connections_count = 0;
        if (! getIntFromJsonObject(&fixed_connections_count, settings, "per-worker-connections-count"))
        {
            LOGF("MuxClient: \"per-worker-connections-count\" is not specified");
            tunnelDestroy(t);
            return NULL;
        }

        if (fixed_connections_count <= 0)
        {
            LOGF("MuxClient: \"per-worker-connections-count\" must be greater than 0, got %d",
                 fixed_connections_count);
            tunnelDestroy(t);
            return NULL;
        }

        size_t fixed_slots_count = (size_t) wc * (size_t) fixed_connections_count;
        if (fixed_slots_count > (SIZE_MAX / sizeof(line_t *)))
        {
            LOGF("MuxClient: \"per-worker-connections-count\" is too large: %d", fixed_connections_count);
            tunnelDestroy(t);
            return NULL;
        }

        ts->fixed_connections_count    = (uint32_t) fixed_connections_count;
        ts->fixed_parent_lines         = memoryAllocate(fixed_slots_count * sizeof(line_t *));
        ts->fixed_next_parent_indexes  = memoryAllocate((size_t) wc * sizeof(uint32_t));

        memorySet(ts->fixed_parent_lines, 0, fixed_slots_count * sizeof(line_t *));
        memorySet(ts->fixed_next_parent_indexes, 0, (size_t) wc * sizeof(uint32_t));
    }

    return t;
}
