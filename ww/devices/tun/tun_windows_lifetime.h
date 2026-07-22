#pragma once

#include <stdbool.h>

typedef struct tun_windows_lifetime_ops_s
{
    void (*begin_shutdown)(void *context);
    bool (*signal_reader)(void *context);
    bool (*join_reader)(void *context);
    bool (*join_writer)(void *context);
    void (*release_writer)(void *context);
    void (*end_session)(void *context);
} tun_windows_lifetime_ops_t;

static inline bool tunWindowsLifetimeShutdown(void *context, const tun_windows_lifetime_ops_t *ops)
{
    ops->begin_shutdown(context);

    // A bounded reader wait is the fallback when signaling fails.
    (void) ops->signal_reader(context);

    bool reader_joined = ops->join_reader(context);
    bool writer_joined = ops->join_writer(context);
    if (! reader_joined || ! writer_joined)
    {
        return false;
    }

    ops->release_writer(context);
    ops->end_session(context);
    return true;
}
