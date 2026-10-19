#pragma once

#include <stdbool.h>

typedef struct tun_windows_lifetime_ops_s
{
    void (*begin_shutdown)(void *context);
    void (*quiesce_reader)(void *context);
    void (*wait_reader_delivery)(void *context);
    void (*wait_writes)(void *context);
    bool (*retire_reader)(void *context);
    void (*end_session)(void *context);
} tun_windows_lifetime_ops_t;

static inline bool tunWindowsLifetimeShutdown(void *context, const tun_windows_lifetime_ops_t *ops)
{
    ops->begin_shutdown(context);

    // Close/rearm admission before retiring worker callbacks and native waits.
    ops->quiesce_reader(context);
    ops->wait_reader_delivery(context);
    ops->wait_writes(context);

    if (! ops->retire_reader(context))
    {
        return false;
    }

    ops->end_session(context);
    return true;
}
