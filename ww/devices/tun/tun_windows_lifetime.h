#pragma once

#include <stdbool.h>

typedef struct tun_windows_lifetime_ops_s
{
    void (*begin_shutdown)(void *context);
    bool (*signal_reader)(void *context);
    void (*wait_reader_delivery)(void *context);
    bool (*join_reader)(void *context);
    bool (*retire_reader)(void *context);
    bool (*join_writer)(void *context);
    bool (*release_writer)(void *context);
    void (*end_session)(void *context);
} tun_windows_lifetime_ops_t;

static inline bool tunWindowsLifetimeShutdown(void *context, const tun_windows_lifetime_ops_t *ops)
{
    ops->begin_shutdown(context);

    // A bounded reader wait is the fallback when signaling fails.
    (void) ops->signal_reader(context);
    ops->wait_reader_delivery(context);

    bool reader_joined = ops->join_reader(context);
    bool writer_joined = ops->join_writer(context);
    if (! reader_joined || ! writer_joined)
    {
        return false;
    }
    if (! ops->retire_reader(context))
    {
        return false;
    }

    if (! ops->release_writer(context))
    {
        return false;
    }
    ops->end_session(context);
    return true;
}
