#include "auth.h"
#include "internal.h"

void vmessserverLinestateInitialize(vmessserver_lstate_t *ls, tunnel_t *t, line_t *l, vmessserver_line_kind_t kind)
{
    *ls = (vmessserver_lstate_t) {
        .tunnel      = t,
        .line        = l,
        .user_handle = userHandleEmpty(),
        .phase       = kVmessServerPhaseWaitInitial,
        .line_kind   = kind,
    };
    bufferqueueInitEmpty(&ls->pending_up);
    bufferqueueInitEmpty(&ls->pending_down);
    buffer_budget_cost_t limits = {kVmessServerMaxPendingBytes, 8U * 1024U * 1024U, kVmessServerMaxPendingBuffers};
    bufferbudgetInit(&ls->upstream_budget, limits);
    bufferbudgetInit(&ls->response_budget, limits);
    bool attached = bufferqueueTryAttachBudget(&ls->pending_up, &ls->upstream_budget) &&
                    bufferqueueTryAttachBudget(&ls->pending_down, &ls->response_budget);
    assert(attached);
    discard               attached;
    vmessserver_tstate_t *ts = tunnelGetState(t);
    atomicAddU64(kind == kVmessServerLineKindClient ? &ts->stats.carriers : &ts->stats.backends, 1);
}

void vmessserverLinestateDestroy(vmessserver_lstate_t *ls)
{
    vmessserver_tstate_t *ts = tunnelGetState(ls->tunnel);
    atomicSubU64(ls->line_kind == kVmessServerLineKindClient ? &ts->stats.carriers : &ts->stats.backends, 1);
    if (ls->crypto_ready)
        atomicSubU64(&ts->stats.applications, 1);
    assert(ls->udp_destination_count == 0);
    memoryFree(ls->udp_destinations);
    vmessserverAuthLineDetach(ls);
    vmessBodyDestroy(&ls->input_crypto);
    vmessBodyDestroy(&ls->output_crypto);
    bufferbudgetReservationRelease(&ls->input_reservation);
    bufferbudgetReservationRelease(&ls->body_reservation);
    bufferbudgetReservationRelease(&ls->response_reservation);
    if (ls->body_buffer)
        lineReuseBuffer(ls->line, ls->body_buffer);
    addresscontextReset(&ls->udp_target);
    if (ls->input_head != NULL)
        lineReuseBuffer(ls->line, ls->input_head);
    bufferqueueDestroy(&ls->pending_up);
    bufferqueueDestroy(&ls->pending_down);
    fallbackReplayDestroy(&ls->fallback, lineGetBufferPool(ls->line));
    bufferbudgetAssertEmpty(&ls->upstream_budget);
    bufferbudgetAssertEmpty(&ls->response_budget);
    if (ls->auth_username != NULL)
    {
        memoryFree(ls->auth_username);
    }
    if (ls->auth_password != NULL)
    {
        memoryFree(ls->auth_password);
    }
    memorySecureZero(&ls->request, sizeof(ls->request));
    memorySecureZero(ls->auth_key.cmd_key, sizeof(ls->auth_key.cmd_key));
    memorySecureZero(ls->auth_key.auth_key, sizeof(ls->auth_key.auth_key));
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
