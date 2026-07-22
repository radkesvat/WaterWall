#pragma once

#include <stdbool.h>

typedef enum capture_windows_join_result_e
{
    kCaptureWindowsJoinResultNotStopped,
    kCaptureWindowsJoinResultStopped,
    kCaptureWindowsJoinResultStoppedHandleReleaseFailed,
} capture_windows_join_result_e;

typedef struct capture_windows_lifetime_ops_s
{
    void (*begin_shutdown)(void *context);
    bool (*has_handle)(const void *context);
    bool (*has_reader)(const void *context);
    bool (*reader_may_be_running)(const void *context);
    bool (*shutdown_handle)(void *context);
    capture_windows_join_result_e (*join_reader)(void *context);
    bool (*close_handle)(void *context);
} capture_windows_lifetime_ops_t;

static inline bool captureWindowsLifetimeRollbackOpen(void *context, const capture_windows_lifetime_ops_t *ops)
{
    if (ops->has_reader(context))
    {
        return false;
    }

    return ! ops->has_handle(context) || ops->close_handle(context);
}

static inline bool captureWindowsLifetimeShutdown(void *context, const capture_windows_lifetime_ops_t *ops)
{
    ops->begin_shutdown(context);

    if (ops->has_handle(context) && ! ops->shutdown_handle(context) && ops->reader_may_be_running(context))
    {
        return false;
    }

    capture_windows_join_result_e join_result = ops->join_reader(context);
    if (join_result == kCaptureWindowsJoinResultNotStopped)
    {
        return false;
    }

    bool handle_closed = ! ops->has_handle(context) || ops->close_handle(context);
    return join_result == kCaptureWindowsJoinResultStopped && handle_closed;
}
