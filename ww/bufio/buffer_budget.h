#pragma once

#include "shiftbuffer.h"

/* Worker-owned accounting only: no buffer ownership or callbacks. A budget has
 * a stable address and outlives its queues and reservations. Limits are immutable;
 * SIZE_MAX is unrestricted, zero is a real allowance. */
typedef struct buffer_budget_cost_s
{
    size_t bytes;
    size_t charge;
    size_t entries;
} buffer_budget_cost_t;

typedef struct buffer_budget_s
{
    buffer_budget_cost_t limits;
    buffer_budget_cost_t used;
} buffer_budget_t;

/* Zero is empty. Move by assignment followed by clearing the source; never copy
 * a live reservation into independently released owners. */
typedef struct buffer_budget_reservation_s
{
    buffer_budget_t     *budget;
    buffer_budget_cost_t cost;
} buffer_budget_reservation_t;

void                 bufferbudgetInit(buffer_budget_t *budget, buffer_budget_cost_t limits);
buffer_budget_cost_t bufferbudgetGetUsage(const buffer_budget_t *budget);
buffer_budget_cost_t bufferbudgetGetLimits(const buffer_budget_t *budget);
bool                 bufferbudgetTryGetCost(const sbuf_t *buf, buffer_budget_cost_t *cost);
bool                 bufferbudgetTryAcquire(buffer_budget_t *budget, buffer_budget_cost_t cost);
void                 bufferbudgetRelease(buffer_budget_t *budget, buffer_budget_cost_t cost);
/* Assert all owners have settled before their storage is reset. */
void bufferbudgetAssertEmpty(const buffer_budget_t *budget);
/* Requires an empty reservation; failure changes nothing. */
bool bufferbudgetTryReserve(buffer_budget_t *budget, const sbuf_t *buf, buffer_budget_reservation_t *reservation);
/* Each component of remaining must be <= its previous value. */
void bufferbudgetReservationReduce(buffer_budget_reservation_t *reservation, buffer_budget_cost_t remaining);
/* Consumes logical bytes only; preserves the original charge and entry. */
void bufferbudgetReservationSetBytes(buffer_budget_reservation_t *reservation, size_t remaining);
/* Empty release is a no-op; live release clears the record. */
void bufferbudgetReservationRelease(buffer_budget_reservation_t *reservation);
