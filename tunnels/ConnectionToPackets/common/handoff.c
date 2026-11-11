#include "structure.h"

#include "capacity.h"
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
    /* Keep both recovery dimensions inside the original per-node ceiling.
     * Tiny fixture inventories with fewer than sixteen slots have no reserve. */
    if (max_entries >= 16 && max_bytes >= 16)
    {
        budget->recovery_max_bytes   = min(max_bytes / 16, (size_t) (1024U * 1024U));
        budget->recovery_max_entries = max_entries / 16;
    }
    return budget;
}

static bool ctpHandoffReserveClass(ctp_handoff_budget_t *budget, size_t charge, bool ingress, bool recovery_eligible,
                                   bool *recovery_reserved)
{
    assert(budget != NULL && charge != 0);
    mutexLock(&budget->lock);
    assert(! budget->detached);
    *recovery_reserved            = false;
    const size_t ordinary_bytes   = budget->bytes - budget->recovery_bytes;
    const size_t ordinary_entries = budget->entries - budget->recovery_entries;
    const bool   local_capacity   = ordinary_entries < budget->max_entries - budget->recovery_max_entries &&
                                charge <= budget->max_bytes - budget->recovery_max_bytes - ordinary_bytes;
    bool admitted = local_capacity && wwLwipCapacityTryReserveExternal(charge);
    if (! admitted && recovery_eligible && budget->recovery_entries < budget->recovery_max_entries &&
        charge <= budget->recovery_max_bytes - budget->recovery_bytes &&
        wwLwipCapacityTryReserveExternalRecovery(charge))
    {
        admitted           = true;
        *recovery_reserved = true;
        budget->recovery_bytes += charge;
        ++budget->recovery_entries;
    }
    bool first_refusal = false;
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
    const size_t ordinary_byte_limit  = budget->max_bytes - budget->recovery_max_bytes;
    const size_t ordinary_entry_limit = budget->max_entries - budget->recovery_max_entries;
    const size_t recovery_bytes       = budget->recovery_bytes;
    const size_t recovery_entries     = budget->recovery_entries;
    const size_t recovery_byte_limit  = budget->recovery_max_bytes;
    const size_t recovery_entry_limit = budget->recovery_max_entries;
    mutexUnlock(&budget->lock);
    if (first_refusal)
        LOGW("ConnectionToPackets: refusing %s packet handoff: %s admission exhausted "
             "(ordinary_charge_bytes=%zu, incoming_charge_bytes=%zu, ordinary_limit_bytes=%zu, "
             "ordinary_entries=%zu, ordinary_entry_limit=%zu, recovery_eligible=%u, "
             "recovery_charge_bytes=%zu, recovery_limit_bytes=%zu, recovery_entries=%zu, "
             "recovery_entry_limit=%zu; further refusals counted silently); inspect stack-stats",
             ingress ? "return" : "output",
             local_capacity ? "lwIP memory" : "node packet handoff",
             ordinary_bytes,
             charge,
             ordinary_byte_limit,
             ordinary_entries,
             ordinary_entry_limit,
             (unsigned) recovery_eligible,
             recovery_bytes,
             recovery_byte_limit,
             recovery_entries,
             recovery_entry_limit);
    return admitted;
}

bool ctpHandoffReserveIngress(ctp_handoff_budget_t *budget, size_t charge, bool recovery_eligible,
                              bool *recovery_reserved)
{
    return ctpHandoffReserveClass(budget, charge, true, recovery_eligible, recovery_reserved);
}

bool ctpHandoffReserveOutput(ctp_handoff_budget_t *budget, size_t charge, bool recovery_eligible,
                             bool *recovery_reserved)
{
    return ctpHandoffReserveClass(budget, charge, false, recovery_eligible, recovery_reserved);
}

static void ctpHandoffReleaseClass(ctp_handoff_budget_t *budget, size_t charge, bool recovery)
{
    assert(budget != NULL && charge != 0);
    mutexLock(&budget->lock);
    assert(budget->entries != 0 && budget->bytes >= charge);
    budget->bytes -= charge;
    --budget->entries;
    if (recovery)
    {
        assert(budget->recovery_entries != 0 && budget->recovery_bytes >= charge);
        budget->recovery_bytes -= charge;
        --budget->recovery_entries;
    }
    const bool destroy = budget->detached && budget->entries == 0;
    mutexUnlock(&budget->lock);
    if (recovery)
        wwLwipCapacityReleaseExternalRecovery(charge);
    else
        wwLwipCapacityReleaseExternal(charge);
    if (destroy)
    {
        mutexDestroy(&budget->lock);
        memoryFree(budget);
    }
}

void ctpHandoffRelease(ctp_handoff_budget_t *budget, size_t charge)
{
    ctpHandoffReleaseClass(budget, charge, false);
}

void ctpHandoffReleaseRecovery(ctp_handoff_budget_t *budget, size_t charge)
{
    ctpHandoffReleaseClass(budget, charge, true);
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
