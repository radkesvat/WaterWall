#include "WireGuardServer/structure.h"

enum
{
    kIngressCloseRetriesPerTick = 32
};

void wireguardserverIngressRetain(ingress_t *ingress)
{
    atomicAdd(&ingress->references, 1);
}

/* Only queued for a previously authenticated ingress with no remaining binding. */
void wireguardserverCloseOrphanIngress(tunnel_t *t, line_t *line)
{
    server_line_t *ls = lineGetState(line, t);
    if (ls->ingress == NULL)
        return;
    wireguardserverDetachIngress(t, line);
    tunnelPrevDownStreamFinish(t, line);
}

/* bindings_lock pins the borrowed line until scheduling takes its own reference.
 * Worker Stop drains the owner inventory if shutdown cancels an accepted close. */
static bool scheduleOrphanClose(server_t *state, ingress_t *ingress)
{
    const bool queued = lineScheduleTask(ingress->line, wireguardserverCloseOrphanIngress, state->tunnel, NULL) ==
                        kLineTaskSubmitAcceptedAsync;
    /* A failed replacement leaves a charged orphan available for another proof.
     * A demotion with no slot must close admission even if its worker is stopping. */
    atomicStore(&ingress->closing, queued || ! ingress->awaiting_proof);
    return queued;
}

/* Try one charged endpoint per arrival. Finish this batch before revisiting
 * refusals or endpoints that lost their last binding in the meantime. */
static bool reclaimIngressSlot(server_t *state)
{
    if (hlist_empty(&state->reclaim_batch))
        hlist_move_list(&state->orphan_ingresses, &state->reclaim_batch);
    if (hlist_empty(&state->reclaim_batch))
        return false;

    ingress_t *orphan = hlist_entry(state->reclaim_batch.first, ingress_t, orphan);
    hlist_del_init(&orphan->orphan);
    if (! scheduleOrphanClose(state, orphan))
    {
        hlist_add_head(&orphan->orphan, &state->orphan_ingresses);
        return false;
    }
    /* The new ingress takes over the old charge. */
    orphan->awaiting_proof = false;
    return true;
}

bool wireguardserverReserveFreshIngress(server_t *state)
{
    mutexLock(&state->bindings_lock);
    bool accepted = state->unauthenticated_ingress < state->max_unauthenticated_ingress;
    if (accepted)
        ++state->unauthenticated_ingress;
    else
        accepted = reclaimIngressSlot(state);
    mutexUnlock(&state->bindings_lock);
    return accepted;
}

/* First proof and line detach both settle their charge under bindings_lock. */
static void releaseIngressCharge(server_t *state, ingress_t *ingress)
{
    hlist_del_init(&ingress->orphan);
    if (ingress->awaiting_proof)
    {
        assert(state->unauthenticated_ingress != 0);
        --state->unauthenticated_ingress;
        ingress->awaiting_proof = false;
    }
}

static void ingressDetachBinding(server_t *state, ingress_t *ingress)
{
    if (ingress->binding_head != NULL || ingress->line == NULL || atomicLoad(&ingress->closing) ||
        ingress->awaiting_proof)
        return;
    if (state->unauthenticated_ingress < state->max_unauthenticated_ingress)
    {
        ++state->unauthenticated_ingress;
        ingress->awaiting_proof = true;
        hlist_add_head(&ingress->orphan, &state->orphan_ingresses);
    }
    else if (! scheduleOrphanClose(state, ingress))
        hlist_add_head(&ingress->orphan, &state->deferred_closes);
}

/* A refused owner submission has no queued task. Retry a bounded share each
 * tick, finishing the current batch before revisiting failures and new arrivals. */
void wireguardserverRetryOrphanCloses(server_t *state)
{
    mutexLock(&state->bindings_lock);
    if (hlist_empty(&state->retry_closes))
        hlist_move_list(&state->deferred_closes, &state->retry_closes);
    for (unsigned i = 0; i < kIngressCloseRetriesPerTick && ! hlist_empty(&state->retry_closes); ++i)
    {
        ingress_t *ingress = hlist_entry(state->retry_closes.first, ingress_t, orphan);
        hlist_del_init(&ingress->orphan);
        if (! scheduleOrphanClose(state, ingress))
            hlist_add_head(&ingress->orphan, &state->deferred_closes);
    }
    mutexUnlock(&state->bindings_lock);
}

/* When both gates are needed, take bindings_lock before the ingress lock. */
bool wireguardserverIngressAvailable(ingress_t *ingress, bool require_writable)
{
    mutexLock(&ingress->lock);
    const bool available =
        ingress->line != NULL && ! atomicLoad(&ingress->closing) && (! require_writable || ! ingress->paused);
    mutexUnlock(&ingress->lock);
    return available;
}

void wireguardserverIngressRelease(void *argument)
{
    ingress_t *ingress = argument;
    if (ingress != NULL && atomicSub(&ingress->references, 1) == 1)
    {
        assert(ingress->line == NULL);
        mutexDestroy(&ingress->lock);
        memoryFree(ingress);
    }
}

void wireguardserverSetBindingIngress(binding_t *binding, ingress_t *ingress)
{
    ingress_t *old = binding->ingress;
    if (old == ingress)
        return;
    if (old != NULL)
    {
        wireguardserverDiscardPending(binding);
        if (binding->ingress_previous != NULL)
            binding->ingress_previous->ingress_next = binding->ingress_next;
        else
            old->binding_head = binding->ingress_next;
        if (binding->ingress_next != NULL)
            binding->ingress_next->ingress_previous = binding->ingress_previous;
        ingressDetachBinding(binding->server, old);
        wireguardserverIngressRelease(old);
    }
    binding->ingress          = ingress;
    binding->ingress_previous = binding->ingress_next = NULL;
    if (ingress != NULL)
    {
        wireguardserverIngressRetain(ingress);
        binding->ingress_next = ingress->binding_head;
        if (binding->ingress_next != NULL)
            binding->ingress_next->ingress_previous = binding;
        ingress->binding_head = binding;
        releaseIngressCharge(binding->server, ingress);
    }
}

void wireguardserverDetachIngress(tunnel_t *t, line_t *line)
{
    server_t      *state   = tunnelGetState(t);
    server_line_t *ls      = lineGetState(line, t);
    ingress_t     *ingress = ls->ingress;
    ls->ingress            = NULL;
    if (ingress == NULL)
        return;
    if (ingress->previous != NULL)
        ingress->previous->next = ingress->next;
    else
        state->ingress_heads[ingress->worker] = ingress->next;
    if (ingress->next != NULL)
        ingress->next->previous = ingress->previous;
    mutexLock(&state->bindings_lock);
    mutexLock(&ingress->lock);
    ingress->line = NULL;
    releaseIngressCharge(state, ingress);
    atomicSub(&state->ingress_count, 1);
    mutexUnlock(&ingress->lock);
    for (binding_t *binding = ingress->binding_head; binding != NULL; binding = binding->ingress_next)
        wireguardserverDiscardPending(binding);
    mutexUnlock(&state->bindings_lock);
    lineUnref(line);
    wireguardserverIngressRelease(ingress);
}
