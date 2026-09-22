#include "structure.h"

/* Step results select the pump's next action, independently of success or failure. */
typedef enum pump_step_result_e
{
    kPumpStepFallThrough, // No callback ran; the next step may inspect state.
    kPumpStepRecheck      // Restart liveness and permission checks before another step.
} pump_step_result_t;

/* The pump retains both exact lines. Physical life alone does not preserve the
 * association: close clears both states before its first outward callback. */
static bool associationAlive(tunnel_t *t, line_t *next_line, line_t *prev_line)
{
    if (! lineIsAlive(next_line) || ! lineIsAlive(prev_line))
        return false;
    trojanclient_lstate_t *ls      = lineGetState(next_line, t);
    trojanclient_lstate_t *prev_ls = lineGetState(prev_line, t);
    return ls->phase != kTrojanClientPhaseClosed && prev_ls->phase != kTrojanClientPhaseClosed &&
           (next_line == prev_line || (ls->app_line == prev_line && prev_ls->carrier_line == next_line));
}

/* Steps share the pump's retained lines and reentrancy guard. Callbacks and close
 * require Recheck; partial UDP header gathering can still FallThrough. */
static pump_step_result_t notifyPausedProducers(tunnel_t *t, line_t *next_line, line_t *prev_line,
                                                trojanclient_lstate_t *ls)
{
    /* Publish notification state before a callback can reenter. */
    if (ls->next_paused && ! ls->prev_pause_sent)
    {
        ls->prev_pause_sent = true;
        tunnelPrevDownStreamPause(t, prev_line);
        return kPumpStepRecheck;
    }
    if (ls->prev_paused && ! ls->next_pause_sent)
    {
        ls->next_pause_sent = true;
        tunnelNextUpStreamPause(t, next_line);
        return kPumpStepRecheck;
    }
    return kPumpStepFallThrough;
}

static pump_step_result_t advanceEstablishment(tunnel_t *t, line_t *next_line, line_t *prev_line,
                                               trojanclient_lstate_t *ls, trojanclient_lstate_t *prev_ls)
{
    if (ls->next_established && ! ls->request_sent && ! ls->next_paused)
    {
        ls->request_sent = true;
        if (! trojanclientSendInitialRequest(t, next_line, ls))
        {
            if (associationAlive(t, next_line, prev_line))
                trojanclientCloseLine(t, next_line, kTrojanClientCloseInternal);
        }
        return kPumpStepRecheck;
    }
    if (ls->request_sent && ls->phase == kTrojanClientPhaseIdle)
    {
        tunnelPrevDownStreamEst(t, prev_line);
        /* Input received during Est remains queued until this callback returns. */
        if (associationAlive(t, next_line, prev_line))
            ls->phase = prev_ls->phase = kTrojanClientPhaseEstablished;
        return kPumpStepRecheck;
    }
    return kPumpStepFallThrough;
}

/* Payload steps run only after establishment and forward at most one buffer. */
static pump_step_result_t forwardQueuedUpstream(tunnel_t *t, line_t *next_line, line_t *prev_line,
                                                trojanclient_lstate_t *ls, trojanclient_lstate_t *prev_ls)
{
    if (ls->next_paused || bufferqueueGetBufCount(&prev_ls->pending_up) == 0)
        return kPumpStepFallThrough;
    sbuf_t *buf = bufferqueuePopFront(&prev_ls->pending_up);
    if (next_line != prev_line && ! trojanclientWrapUdpPayload(prev_line, &buf, &prev_ls->target_addr))
    {
        lineReuseBuffer(prev_line, buf);
        trojanclientCloseLine(t, next_line, kTrojanClientCloseInternal);
        return kPumpStepRecheck;
    }
    tunnelNextUpStreamPayload(t, next_line, buf);
    return kPumpStepRecheck;
}

static pump_step_result_t forwardQueuedDownstream(tunnel_t *t, line_t *next_line, line_t *prev_line,
                                                  trojanclient_lstate_t *ls)
{
    if (ls->prev_paused)
        return kPumpStepFallThrough;
    if (next_line == prev_line)
    {
        if (bufferqueueGetBufCount(&ls->pending_down) == 0)
            return kPumpStepFallThrough;
        tunnelPrevDownStreamPayload(t, prev_line, bufferqueuePopFront(&ls->pending_down));
        return kPumpStepRecheck;
    }

    int header = trojanclientReadUdpHeader(ls);
    if (header < 0)
    {
        trojanclientCloseLine(t, next_line, kTrojanClientCloseInternal);
        return kPumpStepRecheck;
    }
    if (header == 1 && ls->receive_bytes - ls->header_filled >= ls->body_length)
    {
        sbuf_t *body = trojanclientExtractUdpBody(ls);
        tunnelPrevDownStreamPayload(t, prev_line, body);
        return kPumpStepRecheck;
    }
    return kPumpStepFallThrough;
}

static pump_step_result_t notifyResumedProducers(tunnel_t *t, line_t *next_line, line_t *prev_line,
                                                 trojanclient_lstate_t *ls)
{
    if (! ls->next_paused && ls->prev_pause_sent)
    {
        ls->prev_pause_sent = false;
        tunnelPrevDownStreamResume(t, prev_line);
        return kPumpStepRecheck;
    }
    if (! ls->prev_paused && ls->next_pause_sent)
    {
        ls->next_pause_sent = false;
        tunnelNextUpStreamResume(t, next_line);
        return kPumpStepRecheck;
    }
    return kPumpStepFallThrough;
}

void trojanclientPump(tunnel_t *t, line_t *next_line)
{
    trojanclient_lstate_t *ls = lineGetState(next_line, t);
    if (ls->phase == kTrojanClientPhaseClosed || ls->pumping)
        return;
    line_t *prev_line = ls->kind == kTrojanClientLineKindUdpCarrier ? ls->app_line : next_line;
    assert(prev_line != NULL);
    lineRef(next_line);
    if (prev_line != next_line)
        lineRef(prev_line);
    trojanclient_lstate_t *prev_ls = lineGetState(prev_line, t);
    ls->pumping                    = true;
    while (associationAlive(t, next_line, prev_line))
    {
        if (notifyPausedProducers(t, next_line, prev_line, ls) == kPumpStepRecheck)
            continue;
        if (advanceEstablishment(t, next_line, prev_line, ls, prev_ls) == kPumpStepRecheck)
            continue;
        if (ls->phase == kTrojanClientPhaseEstablished)
        {
            if (forwardQueuedUpstream(t, next_line, prev_line, ls, prev_ls) == kPumpStepRecheck)
                continue;
            if (forwardQueuedDownstream(t, next_line, prev_line, ls) == kPumpStepRecheck)
                continue;
        }
        /* Drain ready work before Resume, but let incomplete UDP frames receive more input. */
        if (notifyResumedProducers(t, next_line, prev_line, ls) == kPumpStepRecheck)
            continue;
        break;
    }
    if (associationAlive(t, next_line, prev_line))
        ls->pumping = false;
    if (prev_line != next_line)
        lineUnref(prev_line);
    lineUnref(next_line);
}

void trojanclientOnNextEstablished(tunnel_t *t, line_t *l, trojanclient_lstate_t *ls)
{
    if (ls->phase == kTrojanClientPhaseClosed || ls->next_established)
        return;
    ls->next_established = true;
    trojanclientPump(t, l);
}

void trojanclientSetPrevPaused(tunnel_t *t, line_t *l, bool paused)
{
    trojanclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kTrojanClientPhaseClosed)
        return;
    line_t *next_line = ls->kind == kTrojanClientLineKindUdpApp ? ls->carrier_line : l;
    assert(next_line != NULL);
    trojanclient_lstate_t *next_ls = lineGetState(next_line, t);
    next_ls->prev_paused           = paused;
    trojanclientPump(t, next_line);
}
