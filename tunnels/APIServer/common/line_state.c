#include "APIServer/structure.h"
#include "loggers/network_logger.h"

bool apiserverReserve(apiserver_lstate_t *ls, size_t charge)
{
    apiserver_tstate_t *ts = tunnelGetState(ls->tunnel);
    if (! nodeApiDomainTryReserve(ts->domain, charge))
        return false;
    if (! bufferbudgetTryAcquire(&ls->budget, (buffer_budget_cost_t) {.charge = charge}))
    {
        nodeApiDomainRelease(ts->domain, charge);
        return false;
    }
    return true;
}

void apiserverRelease(apiserver_lstate_t *ls, size_t charge)
{
    apiserver_tstate_t *ts = tunnelGetState(ls->tunnel);
    bufferbudgetRelease(&ls->budget, (buffer_budget_cost_t) {.charge = charge});
    nodeApiDomainRelease(ts->domain, charge);
}

void apiserverAbandonJob(apiserver_lstate_t *ls)
{
    if (ls->job)
    {
        node_api_job_t *job = ls->job;
        ls->job             = NULL;
        nodeApiJobAbandon(job);
        nodeApiJobRelease(job);
    }
}

void apiserverLinestateDestroy(apiserver_lstate_t *ls)
{
    apiserver_tstate_t *ts = tunnelGetState(ls->tunnel);
    if (ls->timer)
    {
        weventSetUserData(ls->timer, NULL);
        wtimerDelete(ls->timer);
        ls->timer = NULL;
    }
    apiserverAbandonJob(ls);
    while (ls->input_head)
    {
        api_input_t *input = ls->input_head;
        ls->input_head     = input->next;
        memorySecureZero(sbufGetMutablePtr(input->buffer), sbufGetLength(input->buffer));
        lineReuseBuffer(ls->line, input->buffer);
        apiserverRelease(ls, input->charge);
        memoryFree(input);
    }
    while (ls->requests)
        apiserverReleaseRequest(ls);
    if (ls->frame)
    {
        apiserverRelease(ls, ls->frame_capacity);
        memorySecureZero(ls->frame, ls->frame_used);
        memoryFree(ls->frame);
    }
    if (ls->output)
    {
        apiserverRelease(ls, ls->output_size);
        memorySecureZero(ls->output, ls->output_size);
        memoryFree(ls->output);
    }
    *ls->previous = ls->next;
    if (ls->next)
        ls->next->previous = ls->previous;
    atomic_fetch_sub(&ts->session_count, 1);
    apiserverRelease(ls, sizeof(*ls));
    bufferbudgetAssertEmpty(&ls->budget);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}

void apiserverCloseSession(tunnel_t *t, line_t *line)
{
    apiserverLinestateDestroy(lineGetState(line, t));
    /* This endpoint borrows the normal line. Its creator closes downstream. */
    tunnelPrevDownStreamFinish(t, line);
}

uint64_t apiserverNextToken(apiserver_tstate_t *ts)
{
    uint64_t previous = atomicIncU64(&ts->serial);
    if (previous == UINT64_MAX)
    {
        LOGF("APIServer: session/request token exhausted");
        abortProgramNow(1);
    }
    return previous + 1;
}

bool apiserverLinestateInitialize(tunnel_t *t, line_t *line)
{
    apiserver_tstate_t *ts = tunnelGetState(t);
    apiserver_lstate_t *ls = lineGetState(line, t);
    *ls                    = (apiserver_lstate_t) {.tunnel = t, .line = line};
    bufferbudgetInit(&ls->budget, (buffer_budget_cost_t) {.charge = ts->limits.max_line_memory});
    w_atomic_uint_value_t count    = atomic_load(&ts->session_count);
    bool                  admitted = false;
    while (count < ts->limits.max_sessions && ! atomic_load(&ts->stopping) && nodeApiAdmissionIsOpen())
        if (atomic_compare_exchange_weak(&ts->session_count, &count, count + 1))
        {
            admitted = true;
            break;
        }
    if (! admitted || ! apiserverReserve(ls, sizeof(*ls)))
    {
        if (admitted)
            atomic_fetch_sub(&ts->session_count, 1);
        memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
        return false;
    }
    wid_t wid         = lineGetWID(line);
    ls->session_token = apiserverNextToken(ts);
    ls->previous      = &ts->sessions[wid];
    ls->next          = ts->sessions[wid];
    if (ls->next)
        ls->next->previous = &ls->next;
    ts->sessions[wid] = ls;
    ls->idle_deadline = nodeApiNowMs() + ts->limits.idle_timeout_ms;
    return true;
}
