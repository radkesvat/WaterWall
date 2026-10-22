#include "structure.h"

#include "loggers/network_logger.h"

ctp_handoff_budget_t *ctpHandoffBudgetCreate(size_t max_bytes, size_t max_entries)
{
    ctp_handoff_budget_t *budget = memoryAllocateZero(sizeof(*budget));
    if (! mutexTryInit(&budget->lock))
    {
        memoryFree(budget);
        return NULL;
    }
    budget->max_bytes   = max_bytes;
    budget->max_entries = max_entries;
    return budget;
}

bool ctpHandoffReserve(ctp_handoff_budget_t *budget, size_t charge, bool ingress)
{
    assert(budget != NULL && charge != 0);
    mutexLock(&budget->lock);
    assert(! budget->detached);
    const bool admitted      = budget->entries < budget->max_entries && charge <= budget->max_bytes - budget->bytes;
    bool       first_refusal = false;
    if (admitted)
    {
        budget->bytes += charge;
        ++budget->entries;
    }
    else
    {
        uint64_t *refused = ingress ? &budget->ingress_refused : &budget->egress_refused;
        first_refusal     = *refused == 0;
        if (*refused != UINT64_MAX)
            ++*refused;
    }
    mutexUnlock(&budget->lock);
    if (first_refusal)
        LOGW("ConnectionToPackets: %s packet handoff budget exhausted (further refusals counted silently)",
             ingress ? "return" : "output");
    return admitted;
}

void ctpHandoffRelease(ctp_handoff_budget_t *budget, size_t charge)
{
    assert(budget != NULL && charge != 0);
    mutexLock(&budget->lock);
    assert(budget->entries != 0 && budget->bytes >= charge);
    budget->bytes -= charge;
    --budget->entries;
    const bool destroy = budget->detached && budget->entries == 0;
    mutexUnlock(&budget->lock);
    if (destroy)
    {
        mutexDestroy(&budget->lock);
        memoryFree(budget);
    }
}

void ctpHandoffBudgetDetach(ctp_handoff_budget_t *budget)
{
    if (budget == NULL)
        return;
    mutexLock(&budget->lock);
    assert(! budget->detached);
    budget->detached               = true;
    const bool     destroy         = budget->entries == 0;
    const uint64_t ingress_refused = budget->ingress_refused;
    const uint64_t egress_refused  = budget->egress_refused;
    mutexUnlock(&budget->lock);
    if (ingress_refused != 0 || egress_refused != 0)
        LOGI("ConnectionToPackets: packet handoff refusals: return=%llu output=%llu",
             (unsigned long long) ingress_refused,
             (unsigned long long) egress_refused);
    if (destroy)
    {
        mutexDestroy(&budget->lock);
        memoryFree(budget);
    }
}
