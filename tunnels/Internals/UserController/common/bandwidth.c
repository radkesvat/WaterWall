#include "structure.h"

#include "loggers/network_logger.h"

static usercontroller_lstate_t *usercontrollerBandwidthLineState(usercontroller_direction_t *direction)
{
    return lineGetState(direction->line, direction->tunnel);
}

static user_bandwidth_direction_t usercontrollerBandwidthUserDirection(usercontroller_direction_t *direction)
{
    const usercontroller_lstate_t *ls = usercontrollerBandwidthLineState(direction);
    return direction->upstream != ls->started_from_next ? kUserBandwidthUpload : kUserBandwidthDownload;
}

static bool usercontrollerBandwidthStopping(usercontroller_direction_t *direction)
{
    const usercontroller_tstate_t *ts = tunnelGetState(direction->tunnel);
    return atomicLoadExplicit(&ts->shaping_stopping, memory_order_acquire) ||
           (ts->worker_states != NULL && ts->worker_states[lineGetWID(direction->line)].quiesced);
}

static traffic_shaper_preview_t usercontrollerBandwidthPreview(void *context, size_t requested, bool queued)
{
    usercontroller_direction_t *direction = context;
    usercontroller_tstate_t    *ts        = tunnelGetState(direction->tunnel);
    usercontroller_lstate_t    *ls        = usercontrollerBandwidthLineState(direction);
    if (usercontrollerBandwidthStopping(direction))
        return (traffic_shaper_preview_t) {.reject = true};
    const user_bandwidth_result_t result =
        authenticationclientUserBandwidthPreview(ts->auth_client_tunnel,
                                                 &ls->handle,
                                                 usercontrollerBandwidthUserDirection(direction),
                                                 queued ? direction->ticket : 0,
                                                 requested,
                                                 ls->payload_mode == kUserControllerPayloadDatagram);
    return (traffic_shaper_preview_t) {
        .bytes = (size_t) min(result.grant, (uint64_t) SIZE_MAX),
        .retry_ms =
            result.decision == kUserDeliveryWait ? (uint32_t) max(UINT64_C(1), min(result.retry_ms, UINT64_C(100))) : 0,
        .reject = result.decision == kUserDeliveryReject};
}

static traffic_shaper_commit_t usercontrollerBandwidthCommit(void *context, size_t bytes, bool queued, bool remaining)
{
    usercontroller_direction_t    *direction = context;
    usercontroller_tstate_t       *ts        = tunnelGetState(direction->tunnel);
    usercontroller_lstate_t       *ls        = usercontrollerBandwidthLineState(direction);
    const user_delivery_decision_t result =
        authenticationclientUserCommitDelivery(ts->auth_client_tunnel,
                                               &ls->handle,
                                               usercontrollerBandwidthUserDirection(direction),
                                               queued ? direction->ticket : 0,
                                               bytes,
                                               ls->payload_mode == kUserControllerPayloadDatagram,
                                               remaining);
    switch (result)
    {
    case kUserDeliveryForward:
        return kTrafficShaperForward;
    case kUserDeliveryForwardClose:
        return kTrafficShaperForwardClose;
    case kUserDeliveryWait:
        return kTrafficShaperWait;
    case kUserDeliveryReject:
        return kTrafficShaperReject;
    }
    LOGF("UserController: invalid delivery decision");
    abortProgramNow(1);
}

static void usercontrollerBandwidthForward(void *context, sbuf_t *buf)
{
    usercontroller_direction_t *direction = context;
    if (direction->upstream)
        tunnelNextUpStreamPayload(direction->tunnel, direction->line, buf);
    else
        tunnelPrevDownStreamPayload(direction->tunnel, direction->line, buf);
}

static void usercontrollerBandwidthPressure(void *context, bool paused)
{
    usercontroller_direction_t *direction = context;
    if (direction->upstream)
    {
        if (paused)
            tunnelPrevDownStreamPause(direction->tunnel, direction->line);
        else
            tunnelPrevDownStreamResume(direction->tunnel, direction->line);
    }
    else
    {
        if (paused)
            tunnelNextUpStreamPause(direction->tunnel, direction->line);
        else
            tunnelNextUpStreamResume(direction->tunnel, direction->line);
    }
}

static void usercontrollerBandwidthClose(void *context)
{
    usercontroller_direction_t *direction = context;
    usercontrollerCloseLine(direction->tunnel, direction->line, kUserControllerCloseInternal);
}

static bool usercontrollerBandwidthReserve(void *context, buffer_budget_cost_t cost)
{
    usercontroller_direction_t *direction = context;
    usercontroller_tstate_t    *ts        = tunnelGetState(direction->tunnel);
    usercontroller_lstate_t    *ls        = usercontrollerBandwidthLineState(direction);
    bool                        created   = direction->ticket == 0;
    if (created)
    {
        direction->ticket = authenticationclientUserBandwidthRegister(
            ts->auth_client_tunnel, &ls->handle, usercontrollerBandwidthUserDirection(direction));
        if (direction->ticket == 0)
            return false;
    }
    if (authenticationclientUserBandwidthReserve(ts->auth_client_tunnel, &ls->handle, direction->ticket, cost))
        return true;
    if (created)
    {
        authenticationclientUserBandwidthCancel(
            ts->auth_client_tunnel, &ls->handle, usercontrollerBandwidthUserDirection(direction), direction->ticket);
        direction->ticket = 0;
    }
    return false;
}

static void usercontrollerBandwidthRelease(void *context, buffer_budget_cost_t cost)
{
    usercontroller_direction_t *direction = context;
    usercontroller_tstate_t    *ts        = tunnelGetState(direction->tunnel);
    usercontroller_lstate_t    *ls        = usercontrollerBandwidthLineState(direction);
    assert(direction->ticket != 0);
    authenticationclientUserBandwidthRelease(ts->auth_client_tunnel, &ls->handle, direction->ticket, cost);
}

static void usercontrollerBandwidthStateChanged(void *context, bool has_work, bool paused)
{
    usercontroller_direction_t *direction = context;
    usercontroller_tstate_t    *ts        = tunnelGetState(direction->tunnel);
    usercontroller_lstate_t    *ls        = usercontrollerBandwidthLineState(direction);
    if (direction->ticket == 0)
        return;
    if (! has_work)
    {
        authenticationclientUserBandwidthCancel(
            ts->auth_client_tunnel, &ls->handle, usercontrollerBandwidthUserDirection(direction), direction->ticket);
        direction->ticket = 0;
        return;
    }
    authenticationclientUserBandwidthSetEligible(ts->auth_client_tunnel,
                                                 &ls->handle,
                                                 usercontrollerBandwidthUserDirection(direction),
                                                 direction->ticket,
                                                 ! paused && ! usercontrollerBandwidthStopping(direction));
}

static const traffic_shaper_ops_t usercontrollerBandwidthOps = {
    .preview       = usercontrollerBandwidthPreview,
    .commit        = usercontrollerBandwidthCommit,
    .forward       = usercontrollerBandwidthForward,
    .pressure      = usercontrollerBandwidthPressure,
    .close         = usercontrollerBandwidthClose,
    .reserve       = usercontrollerBandwidthReserve,
    .release       = usercontrollerBandwidthRelease,
    .state_changed = usercontrollerBandwidthStateChanged,
};

void usercontrollerBandwidthInitialize(tunnel_t *t, line_t *l)
{
    usercontroller_lstate_t *ls = lineGetState(l, t);
    bufferbudgetInit(&ls->budget,
                     (buffer_budget_cost_t) {.bytes = 1024U * 1024U, .charge = 2U * 1024U * 1024U, .entries = 256});
    for (unsigned i = 0; i < 2; ++i)
    {
        usercontroller_direction_t *direction = &ls->directions[i];
        direction->tunnel                     = t;
        direction->line                       = l;
        direction->upstream                   = i == 0;
        trafficshaperInit(&direction->shaper,
                          l,
                          &ls->budget,
                          &usercontrollerBandwidthOps,
                          direction,
                          ls->payload_mode == kUserControllerPayloadDatagram ? kTrafficShaperDatagram
                                                                             : kTrafficShaperStream,
                          0,
                          true);
    }
}

void usercontrollerBandwidthQuiesce(usercontroller_lstate_t *ls)
{
    for (unsigned i = 0; i < 2; ++i)
        trafficshaperQuiesce(&ls->directions[i].shaper);
}

void usercontrollerBandwidthDestroy(usercontroller_lstate_t *ls)
{
    for (unsigned i = 0; i < 2; ++i)
        trafficshaperDestroy(&ls->directions[i].shaper);
    bufferbudgetAssertEmpty(&ls->budget);
}

void usercontrollerBandwidthSubmit(tunnel_t *t, line_t *l, sbuf_t *buf, bool upstream)
{
    usercontroller_lstate_t    *ls        = lineGetState(l, t);
    usercontroller_direction_t *direction = &ls->directions[upstream ? 0 : 1];
    if (usercontrollerBandwidthStopping(direction))
    {
        lineReuseBuffer(l, buf);
        usercontrollerCloseLine(t, l, kUserControllerCloseInternal);
        return;
    }
    if (ls->payload_mode == kUserControllerPayloadDatagram && sbufGetLength(buf) > 65535U)
    {
        lineReuseBuffer(l, buf);
        return;
    }
    // Unlimited, empty directions keep the transparent path, including payload
    // arriving through advisory Pause. A configuration race is revalidated by
    // the same commit used by queued delivery; Wait enters bounded retention.
    if (trafficshaperPending(&direction->shaper) == 0)
    {
        usercontroller_tstate_t *ts = tunnelGetState(t);
        user_bandwidth_result_t  preview =
            authenticationclientUserBandwidthPreview(ts->auth_client_tunnel,
                                                     &ls->handle,
                                                     usercontrollerBandwidthUserDirection(direction),
                                                     0,
                                                     sbufGetLength(buf),
                                                     ls->payload_mode == kUserControllerPayloadDatagram);
        if (! preview.limited && preview.decision == kUserDeliveryForward)
        {
            traffic_shaper_commit_t decision =
                usercontrollerBandwidthCommit(direction, sbufGetLength(buf), false, false);
            if (decision == kTrafficShaperForward || decision == kTrafficShaperForwardClose)
            {
                if (decision == kTrafficShaperForwardClose)
                {
                    lineRef(l);
                    usercontrollerBandwidthForward(direction, buf);
                    if (lineIsAlive(l))
                        usercontrollerCloseLine(t, l, kUserControllerCloseInternal);
                    lineUnref(l);
                }
                else
                    usercontrollerBandwidthForward(direction, buf);
                return;
            }
            if (decision == kTrafficShaperReject)
            {
                lineReuseBuffer(l, buf);
                usercontrollerCloseLine(t, l, kUserControllerCloseInternal);
                return;
            }
        }
    }
    const bool              datagram = ls->payload_mode == kUserControllerPayloadDatagram;
    traffic_shaper_submit_t result   = trafficshaperSubmit(&direction->shaper, buf);
    if (result == kTrafficShaperRefused)
    {
        lineReuseBuffer(l, buf);
        if (! datagram)
            usercontrollerCloseLine(t, l, kUserControllerCloseInternal);
    }
}

void usercontrollerBandwidthSetExternalPause(tunnel_t *t, line_t *l, bool upstream, bool paused)
{
    usercontroller_lstate_t    *ls        = lineGetState(l, t);
    usercontroller_direction_t *direction = &ls->directions[upstream ? 0 : 1];
    bool                        limited   = false;
    if (ls->managed)
    {
        usercontroller_tstate_t *ts = tunnelGetState(t);
        user_bandwidth_result_t  result =
            authenticationclientUserBandwidthPreview(ts->auth_client_tunnel,
                                                     &ls->handle,
                                                     usercontrollerBandwidthUserDirection(direction),
                                                     direction->ticket,
                                                     0,
                                                     ls->payload_mode == kUserControllerPayloadDatagram);
        limited = result.limited;
    }
    if (! ls->managed ||
        (! limited && trafficshaperPending(&direction->shaper) == 0 && ! direction->shaper.locally_paused))
    {
        direction->shaper.externally_paused = paused;
        usercontrollerBandwidthPressure(direction, paused);
        return;
    }
    trafficshaperSetExternalPause(&direction->shaper, paused);
}
