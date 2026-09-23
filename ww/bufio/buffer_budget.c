#include "buffer_budget.h"

void bufferbudgetInit(buffer_budget_t *budget, buffer_budget_cost_t limits)
{
    *budget = (buffer_budget_t) {.limits = limits};
}

buffer_budget_cost_t bufferbudgetGetUsage(const buffer_budget_t *budget)
{
    return budget->used;
}

buffer_budget_cost_t bufferbudgetGetLimits(const buffer_budget_t *budget)
{
    return budget->limits;
}

bool bufferbudgetTryGetCost(const sbuf_t *buf, buffer_budget_cost_t *cost)
{
    size_t charge;
    if (! sbufTryGetQueueCharge(buf, &charge))
        return false;
    *cost = (buffer_budget_cost_t) {sbufGetLength(buf), charge, 1};
    return true;
}

bool bufferbudgetTryAcquire(buffer_budget_t *budget, buffer_budget_cost_t cost)
{
    assert(budget->used.bytes <= budget->limits.bytes && budget->used.charge <= budget->limits.charge &&
           budget->used.entries <= budget->limits.entries);
    if (cost.bytes > budget->limits.bytes - budget->used.bytes ||
        cost.charge > budget->limits.charge - budget->used.charge ||
        cost.entries > budget->limits.entries - budget->used.entries)
        return false;
    budget->used.bytes += cost.bytes;
    budget->used.charge += cost.charge;
    budget->used.entries += cost.entries;
    return true;
}

void bufferbudgetRelease(buffer_budget_t *budget, buffer_budget_cost_t cost)
{
    assert(cost.bytes <= budget->used.bytes && cost.charge <= budget->used.charge &&
           cost.entries <= budget->used.entries);
    budget->used.bytes -= cost.bytes;
    budget->used.charge -= cost.charge;
    budget->used.entries -= cost.entries;
}

void bufferbudgetAssertEmpty(const buffer_budget_t *budget)
{
    assert(budget->used.bytes == 0 && budget->used.charge == 0 && budget->used.entries == 0);
    discard budget;
}

bool bufferbudgetTryReserve(buffer_budget_t *budget, const sbuf_t *buf, buffer_budget_reservation_t *reservation)
{
    assert(reservation->budget == NULL);
    buffer_budget_cost_t cost;
    if (! bufferbudgetTryGetCost(buf, &cost) || ! bufferbudgetTryAcquire(budget, cost))
        return false;
    *reservation = (buffer_budget_reservation_t) {budget, cost};
    return true;
}

void bufferbudgetReservationReduce(buffer_budget_reservation_t *reservation, buffer_budget_cost_t remaining)
{
    assert(reservation->budget != NULL);
    assert(remaining.bytes <= reservation->cost.bytes && remaining.charge <= reservation->cost.charge &&
           remaining.entries <= reservation->cost.entries);
    bufferbudgetRelease(reservation->budget,
                        (buffer_budget_cost_t) {reservation->cost.bytes - remaining.bytes,
                                                reservation->cost.charge - remaining.charge,
                                                reservation->cost.entries - remaining.entries});
    reservation->cost = remaining;
}

void bufferbudgetReservationSetBytes(buffer_budget_reservation_t *reservation, size_t remaining)
{
    buffer_budget_cost_t cost = reservation->cost;
    cost.bytes                = remaining;
    bufferbudgetReservationReduce(reservation, cost);
}

void bufferbudgetReservationRelease(buffer_budget_reservation_t *reservation)
{
    if (reservation->budget == NULL)
        return;
    bufferbudgetRelease(reservation->budget, reservation->cost);
    *reservation = (buffer_budget_reservation_t) {0};
}
