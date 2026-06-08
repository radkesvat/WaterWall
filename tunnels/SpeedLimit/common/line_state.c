#include "structure.h"

#include "loggers/network_logger.h"

void speedlimitLinestateInitialize(speedlimit_lstate_t *ls, tunnel_t *t, line_t *l)
{
    speedlimit_tstate_t *ts = tunnelGetState(t);

    *ls = (speedlimit_lstate_t) {.tunnel      = t,
                                 .line        = l,
                                 .up_queue    = bufferqueueCreate(kSpeedLimitQueueCap),
                                 .down_queue  = bufferqueueCreate(kSpeedLimitQueueCap),
                                 .up_timer    = NULL,
                                 .down_timer  = NULL,
                                 .line_bucket = {.tokens_units = ts->bucket_capacity_units, .last_refill_ms = 0},
                                 .prev_side_externally_paused = false,
                                 .next_side_externally_paused = false,
                                 .prev_side_locally_paused    = false,
                                 .next_side_locally_paused    = false};
}

void speedlimitLinestateDestroy(speedlimit_lstate_t *ls)
{
    if (ls->up_timer != NULL)
    {
        weventSetUserData(ls->up_timer, NULL);
        wtimerDelete(ls->up_timer);
        ls->up_timer = NULL;
    }

    if (ls->down_timer != NULL)
    {
        weventSetUserData(ls->down_timer, NULL);
        wtimerDelete(ls->down_timer);
        ls->down_timer = NULL;
    }

    bufferqueueDestroy(&ls->up_queue);
    bufferqueueDestroy(&ls->down_queue);

    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(speedlimit_lstate_t)));
}
