#include "APIServer/structure.h"

enum
{
    kApiOutputChunk = 16 * 1024
};

static void sessionTimer(wtimer_t *timer);

static bool stillLive(apiserver_lstate_t *ls, tunnel_t *t, line_t *line)
{
    return lineIsAlive(line) && ls->tunnel == t;
}

static const char *dispatchError(node_api_dispatch_status_t status)
{
    switch (status)
    {
    case kNodeApiDispatchOk:
        return NULL;
    case kNodeApiDispatchTimeout:
        return "timeout";
    case kNodeApiDispatchShuttingDown:
        return "shutting_down";
    case kNodeApiDispatchResponseTooLarge:
        return "response_too_large";
    default:
        return "busy";
    }
}

static bool startRequest(apiserver_lstate_t *ls)
{
    api_request_t      *r  = ls->requests;
    apiserver_tstate_t *ts = tunnelGetState(ls->tunnel);
    assert(r && ! ls->job && ! ls->output);
    tunnel_t                   *target = NULL;
    const node_api_operation_t *op     = NULL;
    const char                 *error  = r->error;
    if (! error)
        error = apiserverAuthorize(ts, r, &target, &op);
    if (error)
        return apiserverPublishResponse(ls, error, NULL, kApiResultError, NULL, 0);
    ls->request_token = apiserverNextToken(ts);
    /* Reserve a small usable handler result independently of a smaller encoded
     * envelope cap. Encoding can then classify a valid result as too large. */
    ls->job = nodeApiJobCreate(ts->domain,
                               target,
                               op,
                               lineGetWID(ls->line),
                               ls->session_token,
                               ls->request_token,
                               r->deadline_ms,
                               r->client,
                               nodemanagerConfigName(ls->tunnel->node->node_manager_config),
                               ls->tunnel->node->name,
                               r->body,
                               r->body_size,
                               max(ts->limits.max_response_envelope, (size_t) kApiMinimumResultAllowance),
                               ts->limits.handler_working_memory);
    if (! ls->job)
        return apiserverPublishResponse(
            ls, nodeApiAdmissionIsOpen() ? "busy" : "shutting_down", NULL, kApiResultError, NULL, 0);
    /* Owner pending state is already visible if refusal cleanup runs inline. */
    node_api_dispatch_status_t result = nodeApiJobSubmit(ls->job);
    if (result != kNodeApiDispatchOk)
    {
        apiserverAbandonJob(ls);
        return apiserverPublishResponse(ls, dispatchError(result), NULL, kApiResultError, NULL, 0);
    }
    return true;
}

static uint64_t minimum(uint64_t current, uint64_t value)
{
    return value && value < current ? value : current;
}

bool apiserverArmTimer(apiserver_lstate_t *ls)
{
    if (ls->timer)
    {
        weventSetUserData(ls->timer, NULL);
        wtimerDelete(ls->timer);
        ls->timer = NULL;
    }
    if (ls->quiesced)
        return true;
    apiserver_tstate_t *ts  = tunnelGetState(ls->tunnel);
    uint64_t            now = nodeApiNowMs();
    uint64_t            due = UINT64_MAX;
    due                     = minimum(due, ls->frame_deadline);
    due                     = minimum(due, ls->output_deadline);
    for (api_request_t *r = ls->requests; r; r = r->next)
        due = minimum(due, r->deadline_ms);
    if (! ls->requests && ! ls->input_head && ! ls->frame_deadline && ! ls->output)
        due = minimum(due, ls->idle_deadline);
    bool parse_more = ls->input_head && ls->request_count < ts->limits.max_queued_requests + 1 &&
                      ! (ls->requests_tail && ls->requests_tail->close);
    /* Immediate replies can exhaust the turn before the next parsed request
     * starts. That runnable head needs a continuation even with no raw input. */
    bool request_ready = ls->requests && ! ls->job && ! ls->output;
    if (parse_more || request_ready || (ls->output && ! ls->output_paused))
        due = minimum(due, now + 1);
    assert(due != UINT64_MAX);
    uint64_t wait = due > now ? due - now : 1;
    if (wait > UINT32_MAX)
        wait = UINT32_MAX;
    ls->timer = wtimerAdd(getWorkerLoop(lineGetWID(ls->line)), sessionTimer, (uint32_t) wait, 1);
    if (! ls->timer)
        return false;
    weventSetUserData(ls->timer, ls);
    return true;
}

static bool checkDeadlines(apiserver_lstate_t *ls)
{
    uint64_t now = nodeApiNowMs();
    for (api_request_t *r = ls->requests ? ls->requests->next : NULL; r; r = r->next)
        if (r->deadline_ms && now >= r->deadline_ms)
            return false; /* Never insert a later timeout ahead of the head reply. */
    if (ls->output_deadline && now >= ls->output_deadline)
        return false;
    if (ls->frame_deadline && now >= ls->frame_deadline)
    {
        if (! apiserverFramingError(ls, "timeout"))
            return false;
    }
    if (ls->requests && ls->requests->deadline_ms && now >= ls->requests->deadline_ms)
    {
        apiserverAbandonJob(ls);
        ls->requests->close = true;
        if (! apiserverPublishResponse(ls, "timeout", NULL, kApiResultError, NULL, 0))
            return false;
    }
    if (! ls->requests && ! ls->input_head && ! ls->frame_deadline && ! ls->output && now >= ls->idle_deadline)
        return false;
    return true;
}

static bool pressure(apiserver_lstate_t *ls)
{
    apiserver_tstate_t *ts     = tunnelGetState(ls->tunnel);
    bool                paused = ls->input_paused;
    if (ls->request_count >= ts->limits.max_queued_requests + 1 ||
        ls->input_bytes >= ts->limits.max_input_bytes - ts->limits.max_input_bytes / 4 ||
        ls->input_fragments >= ts->limits.max_input_fragments - ts->limits.max_input_fragments / 4)
        paused = true;
    else if (ls->request_count <= ts->limits.max_queued_requests / 2 &&
             ls->input_bytes <= ts->limits.max_input_bytes / 2 &&
             ls->input_fragments <= ts->limits.max_input_fragments / 2)
        paused = false;
    if (paused == ls->input_paused)
        return true;
    ls->input_paused = paused;
    tunnel_t *t      = ls->tunnel;
    line_t   *line   = ls->line;
    if (paused)
        tunnelPrevDownStreamPause(t, line);
    else
        tunnelPrevDownStreamResume(t, line);
    return stillLive(ls, t, line);
}

void apiserverProgress(tunnel_t *t, line_t *line)
{
    apiserver_lstate_t *ls = lineGetState(line, t);
    if (ls->processing || ls->quiesced)
        return;
    ls->processing = true;
    lineRef(line);
    bool     good         = checkDeadlines(ls) && apiserverParseInput(ls);
    size_t   output_bytes = 0;
    unsigned responses    = 0;
    while (good && responses < kApiTurnFrames)
    {
        if (! ls->job && ! ls->output && ls->requests)
            good = startRequest(ls);
        if (! good || ! ls->output || ls->output_paused || output_bytes >= kApiTurnBytes)
            break;
        size_t n = ls->output_size - ls->output_offset;
        if (n > kApiOutputChunk)
            n = kApiOutputChunk;
        buffer_pool_fit_t fit;
        buffer_pool_t    *pool    = lineGetBufferPool(line);
        uint16_t          padding = bufferpoolGetLargeBufferPadding(pool);
        if (! bufferpoolQueryBestFit(pool, n, padding, &fit) || ! apiserverReserve(ls, fit.allocation_charge))
        {
            good = false;
            break;
        }
        sbuf_t *out = bufferpoolGetBestFit(pool, (uint32_t) n, padding);
        memcpy(sbufGetMutablePtr(out), ls->output + ls->output_offset, n);
        sbufSetLength(out, (uint32_t) n);
        ls->output_offset += n;
        output_bytes += n;
        /* Transfer ownership and retire this chunk's local reservation before reentry. */
        apiserverRelease(ls, fit.allocation_charge);
        tunnelPrevDownStreamPayload(t, line, out);
        if (! stillLive(ls, t, line))
            goto done;
        if (ls->output_offset == ls->output_size)
        {
            bool close = ls->close_after_output;
            apiserverRelease(ls, ls->output_size);
            memoryFree(ls->output);
            ls->output      = NULL;
            ls->output_size = ls->output_offset = 0;
            ls->output_deadline                 = 0;
            ls->close_after_output              = false;
            apiserverReleaseRequest(ls);
            ls->idle_deadline = nodeApiNowMs() + ((apiserver_tstate_t *) tunnelGetState(t))->limits.idle_timeout_ms;
            ++responses;
            if (close)
            {
                apiserverCloseSession(t, line);
                goto done;
            }
        }
    }
    if (good)
    {
        if (! pressure(ls))
            goto done;
        good = apiserverArmTimer(ls);
    }
    if (! good)
        apiserverCloseSession(t, line);
    else
        ls->processing = false;
done:
    lineUnref(line);
}

static void sessionTimer(wtimer_t *timer)
{
    apiserver_lstate_t *ls = weventGetUserdata(timer);
    assert(ls && ls->timer == timer);
    ls->timer = NULL; /* Due one-shot belongs to pending-event reclamation. */
    apiserverProgress(ls->tunnel, ls->line);
}

void apiserverComplete(void *context, uint64_t session, uint64_t request, const node_api_reply_t *reply)
{
    tunnel_t           *t   = context;
    apiserver_tstate_t *ts  = tunnelGetState(t);
    wid_t               wid = getCurrentEventWorkerWID();
    apiserver_lstate_t *ls  = ts->sessions[wid];
    for (; ls; ls = ls->next)
        if (ls->session_token == session)
            break;
    if (! ls || ls->request_token != request || ! ls->job || ls->quiesced)
        return;
    node_api_job_t *job = ls->job;
    ls->job             = NULL;
    nodeApiJobRelease(job); /* Completion still owns its independent job reference. */
    line_t *line = ls->line;
    if (! apiserverPublishResponse(
            ls, dispatchError(reply->status), reply->operation, reply->result_code, reply->body, reply->body_size))
    {
        apiserverCloseSession(t, line);
        return;
    }
    apiserverProgress(t, line);
}
