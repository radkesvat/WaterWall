#include "runtime.h"

#include "loggers/network_logger.h"

void quicCancelTimer(quic_context_t *context)
{
    if (context->timer != NULL)
    {
        wtimer_t *timer = context->timer;
        context->timer  = NULL;
        weventSetUserData(timer, NULL);
        wtimerDelete(timer);
    }
}

static void quicTimer(wtimer_t *timer)
{
    quic_context_t *context = weventGetUserdata(timer);
    if (context == NULL)
    {
        return;
    }
    assert(getLoopWorkerWID(weventGetLoop(timer)) == lineGetWID(context->line));
    if (! quicEnter(context))
    {
        /* A nested loop cannot recursively enter the protocol driver. */
        return;
    }
    quicPump(context);
    quicLeave(context);
}

void quicArm(quic_context_t *context, bool more_work)
{
    quic_tstate_t *state = tunnelGetState(context->tunnel);
    if (atomicLoadRelaxed(&state->stopping))
    {
        quicCancelTimer(context);
        return;
    }
    uint64_t now      = ww_quic_now_us();
    uint64_t deadline = ww_quic_engine_deadline(context->engine);
    if (deadline == UINT64_MAX && ! more_work)
    {
        quicCancelTimer(context);
        return;
    }
    uint64_t wait = more_work || deadline <= now ? 1 : (deadline - now + 999) / 1000;
    if (wait > UINT32_MAX)
    {
        wait = UINT32_MAX;
    }
    /* wtimerAdd rounds multiples of 100ms down to its coarse grid. Avoid those
     * values so the QUIC deadline is always rounded upward. */
    if (wait >= 1000 && wait % 100 == 0)
    {
        ++wait;
    }
    wloop_t *loop = getWorkerLoop(lineGetWID(context->line));
    wloopUpdateTime(loop);
    if (context->timer != NULL)
    {
        if (! wtimerReset(context->timer, (uint32_t) wait))
        {
            quicFail(context, "owner timer rearm refused");
        }
        return;
    }
    context->timer = wtimerAdd(loop, quicTimer, (uint32_t) wait, INFINITE);
    if (context->timer == NULL)
    {
        quicFail(context, "owner timer admission refused");
        return;
    }
    weventSetUserData(context->timer, context);
}
