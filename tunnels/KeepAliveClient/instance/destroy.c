#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                   context;
    keepaliveclient_tstate_t *ts = tunnelGetState(t);

    /* KeepAliveClient is strictly L4 and borrows every line. All real owners
     * must have completed their drains before final instance destruction. This
     * terminal check is safe even when the chain array itself is not stored in
     * source-to-tail order. */
    mutexLock(&ts->lines_mutex);
    const bool residual_registry = ts->lines_head != NULL;
    mutexUnlock(&ts->lines_mutex);
    if (UNLIKELY(residual_registry))
    {
        LOGF("KeepAliveClient: tunnel destruction found an undrained tracked line");
        abortProgramNow(1);
    }

    if (ts->worker_timers != NULL)
    {
        memoryFree(ts->worker_timers);
        ts->worker_timers = NULL;
    }

    mutexDestroy(&ts->lines_mutex);
    tunnelDestroy(t);
}
