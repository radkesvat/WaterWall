#include "structure.h"

#include "loggers/network_logger.h"

static void speedlimitDrainUpstream(speedlimit_lstate_t *ls)
{
    tunnel_t *t = ls->tunnel;
    line_t   *l = ls->line;

    if (bufferqueueGetBufCount(&ls->up_queue) == 0)
    {
        if (ls->prev_side_locally_paused)
        {
            ls->prev_side_locally_paused = false;
            if (! ls->prev_side_externally_paused)
            {
                tunnelPrevDownStreamResume(t, l);
            }
        }
        return;
    }

    sbuf_t *front = (sbuf_t *) bufferqueueFront(&ls->up_queue);
    assert(front != NULL);

    size_t grant_bytes = speedlimitGrantBytes(t, l, sbufGetLength(front), true);
    if (grant_bytes == 0)
    {
        if (! speedlimitScheduleUpstreamDrain(ls, speedlimitGetRetryDelayMs(t, l)))
        {
            // every byte is still queued, speedlimitLinestateDestroy() recycles all of them
            speedlimitCloseLineOnDrainFailure(ls, NULL);
        }
        return;
    }

    sbuf_t *queued_buf = bufferqueuePopFront(&ls->up_queue);
    sbuf_t *send_buf   = queued_buf;
    if (grant_bytes < sbufGetLength(queued_buf))
    {
        send_buf = sbufSlice(queued_buf, (uint32_t) grant_bytes);
        bufferqueuePushFront(&ls->up_queue, queued_buf);
    }

    if (bufferqueueGetBufCount(&ls->up_queue) > 0)
    {
        uint32_t delay_ms = (speedlimitPeekAvailableUnits(t, l) >= kSpeedLimitUnitsPerByte)
                                ? kSpeedLimitImmediateMs
                                : speedlimitGetRetryDelayMs(t, l);
        if (! speedlimitScheduleUpstreamDrain(ls, delay_ms))
        {
            // send_buf is detached from the queue and must not be forwarded after the close decision
            speedlimitCloseLineOnDrainFailure(ls, send_buf);
            return;
        }
    }
    else if (ls->prev_side_locally_paused)
    {
        if (! speedlimitScheduleUpstreamDrain(ls, kSpeedLimitImmediateMs))
        {
            speedlimitCloseLineOnDrainFailure(ls, send_buf);
            return;
        }
    }

    tunnelNextUpStreamPayload(t, l, send_buf);
}

void speedlimitUpstreamDrainTimerCallback(wtimer_t *timer)
{
    speedlimit_lstate_t *ls = weventGetUserdata(timer);
    if (ls == NULL)
    {
        return;
    }

    ls->up_timer = NULL;
    if (ls->line == NULL || ls->tunnel == NULL || ! lineIsAlive(ls->line))
    {
        return;
    }

    speedlimitDrainUpstream(ls);
}

void speedlimitTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    speedlimit_tstate_t *ts = tunnelGetState(t);
    speedlimit_lstate_t *ls = lineGetState(l, t);

    if (ts->work_mode == kSpeedLimitWorkModeDrop)
    {
        if (speedlimitGrantBytes(t, l, sbufGetLength(buf), false) == sbufGetLength(buf))
        {
            tunnelNextUpStreamPayload(t, l, buf);
        }
        else
        {
            lineReuseBuffer(l, buf);
        }
        return;
    }

    if (bufferqueueGetBufCount(&ls->up_queue) == 0 &&
        speedlimitGrantBytes(t, l, sbufGetLength(buf), false) == sbufGetLength(buf))
    {
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }

    bufferqueuePushBack(&ls->up_queue, buf);

    {
        uint32_t delay_ms = (speedlimitPeekAvailableUnits(t, l) >= kSpeedLimitUnitsPerByte)
                                ? kSpeedLimitImmediateMs
                                : speedlimitGetRetryDelayMs(t, l);
        if (! speedlimitScheduleUpstreamDrain(ls, delay_ms))
        {
            // buf is owned by the queue now, speedlimitLinestateDestroy() recycles it; no Pause may follow
            speedlimitCloseLineOnDrainFailure(ls, NULL);
            return;
        }
    }

    if (! ls->prev_side_locally_paused)
    {
        ls->prev_side_locally_paused = true;
        if (! ls->prev_side_externally_paused)
        {
            tunnelPrevDownStreamPause(t, l);
        }
    }
}
