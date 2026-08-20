#include "structure.h"

#include "loggers/network_logger.h"

static bool muxclientComputeFixedStorageGeometry(size_t workers_count, uint32_t fixed_connections_count,
                                                 size_t *parents_bytes_out, size_t *indexes_bytes_out)
{
    if (parents_bytes_out == NULL || indexes_bytes_out == NULL)
    {
        return false;
    }
    *parents_bytes_out = 0;
    *indexes_bytes_out = 0;

    if (workers_count == 0 || fixed_connections_count == 0 || workers_count > SIZE_MAX / fixed_connections_count)
    {
        return false;
    }

    const size_t slots = workers_count * fixed_connections_count;
    size_t       parents_bytes;
    size_t       indexes_bytes;
    if (! memoryTryComputeArraySize(slots, sizeof(line_t *), &parents_bytes) ||
        ! memoryTryComputeArraySize(workers_count, sizeof(uint32_t), &indexes_bytes))
    {
        return false;
    }

    *parents_bytes_out = parents_bytes;
    *indexes_bytes_out = indexes_bytes;
    return true;
}

tunnel_t *muxclientTunnelCreate(node_t *node)
{
    int wc = getWorkersCount();

    size_t selection_bytes;
    if (wc <= 0 || ! memoryTryComputeArraySize((size_t) wc, sizeof(line_t *), &selection_bytes) ||
        selection_bytes > SIZE_MAX - sizeof(muxclient_tstate_t))
    {
        LOGF("MuxClient: worker selection geometry is not representable");
        return NULL;
    }

    tunnel_t *t = tunnelCreate(node, sizeof(muxclient_tstate_t) + selection_bytes, sizeof(muxclient_lstate_t));
    if (! t)
    {
        return NULL;
    }

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

    t->onPrepare    = &muxclientTunnelOnPrepair;
    t->onStart      = &muxclientTunnelOnStart;
    t->onStop       = &muxclientTunnelOnStop;
    t->onWorkerStop = &muxclientTunnelOnWorkerStop;
    t->onDestroy    = &muxclientTunnelDestroy;

    const cJSON        *settings                     = node->node_settings_json;
    muxclient_tstate_t *ts                           = tunnelGetState(t);
    int                 child_buffer_limit           = kMuxDefaultChildBufferLimit;
    int                 child_buffer_pause_tolerance = kMuxDefaultChildBufferPauseTolerance;
    int                 parent_buffer_limit          = kMuxDefaultParentBufferLimit;
    bool                log_main_line_stats          = false;
    uint32_t            staged_fixed_connections     = 0;

    getIntFromJsonObjectOrDefault(&child_buffer_limit, settings, "child-buffer-limit", kMuxDefaultChildBufferLimit);
    getIntFromJsonObjectOrDefault(
        &child_buffer_pause_tolerance, settings, "child-buffer-pause-tolerance", kMuxDefaultChildBufferPauseTolerance);
    getIntFromJsonObjectOrDefault(&parent_buffer_limit, settings, "parent-buffer-limit", kMuxDefaultParentBufferLimit);
    getBoolFromJsonObjectOrDefault(&log_main_line_stats, settings, "log-main-line-stats", false);
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
    if (parent_buffer_limit < 0)
    {
        LOGF("MuxClient: \"parent-buffer-limit\" must be greater than or equal to 0, got %d", parent_buffer_limit);
        tunnelDestroy(t);
        return NULL;
    }
    ts->child_buffer_limit = (uint32_t) child_buffer_limit;
    ts->child_buffer_pause_tolerance =
        (uint32_t) min((size_t) child_buffer_pause_tolerance, (size_t) child_buffer_limit);
    // This is a per-parent budget, not another per-child limit, so it may
    // intentionally be smaller than child_buffer_limit. Zero disables it.
    ts->parent_buffer_limit = (uint32_t) parent_buffer_limit;
    ts->log_main_line_stats = log_main_line_stats;

    ts->concurrency_mode =
        parseDynamicNumericValueFromJsonObject(settings, "mode", 3, "timer", "counter", "fixed-connections-count")
            .status;

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
        if (! getIntFromJsonObject(&duration, settings, "connection-duration-ms"))
        {
            LOGF("MuxClient: \"connection-duration-ms\" is not specified", duration);
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
            LOGF("MuxClient: \"per-worker-connections-count\" must be greater than 0, got %d", fixed_connections_count);
            tunnelDestroy(t);
            return NULL;
        }

        staged_fixed_connections = (uint32_t) fixed_connections_count;
    }

    line_t  **staged_fixed_parent_lines   = NULL;
    uint32_t *staged_fixed_parent_indexes = NULL;

    if (staged_fixed_connections != 0)
    {
        size_t fixed_parent_bytes;
        size_t fixed_index_bytes;
        if (! muxclientComputeFixedStorageGeometry(
                (size_t) wc, staged_fixed_connections, &fixed_parent_bytes, &fixed_index_bytes))
        {
            LOGF("MuxClient: \"per-worker-connections-count\" is too large: %u", staged_fixed_connections);
            tunnelDestroy(t);
            return NULL;
        }
        staged_fixed_parent_lines = memoryAllocateZero(fixed_parent_bytes);
        if (staged_fixed_parent_lines != NULL)
        {
            staged_fixed_parent_indexes = memoryAllocateZero(fixed_index_bytes);
        }
    }

    if (staged_fixed_connections != 0 && (staged_fixed_parent_lines == NULL || staged_fixed_parent_indexes == NULL))
    {
        memoryFree(staged_fixed_parent_lines);
        memoryFree(staged_fixed_parent_indexes);
        tunnelDestroy(t);
        return NULL;
    }

    ts->fixed_connections_count   = staged_fixed_connections;
    ts->fixed_parent_lines        = staged_fixed_parent_lines;
    ts->fixed_next_parent_indexes = staged_fixed_parent_indexes;

    return t;
}
