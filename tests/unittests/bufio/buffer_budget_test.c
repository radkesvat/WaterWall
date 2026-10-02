/*
 * Covers: Transactional byte, retained-allocation charge and entry limits for buffer-budget admission.
 * Setup: Inline deterministic costs and one real padded sbuf; no workers or runtime fixture.
 * Cases: Independent dimensions, exact bounds, zero limits, SIZE_MAX overflow, reservation byte updates,
 * competing reservations and repeated release.
 * Checks: Refusal preserves usage, reservation updates retain charge/entry costs, only one competing
 * reservation succeeds and every accepted cost settles to an empty budget.
 * CTest: waterwall.buffer_budget_unit
 */
#include "buffer_budget.h"

#include "test_assert.h"

#include <stdio.h>
#include <stdlib.h>

#define check(condition) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, "buffer budget contract failed")

int main(void)
{
    testCaseSet("buffer_budget_test");
    buffer_budget_t budget;
    for (unsigned dimension = 0; dimension < 3; ++dimension)
    {
        buffer_budget_cost_t limits = {SIZE_MAX, SIZE_MAX, SIZE_MAX};
        buffer_budget_cost_t over   = {1, 1, 1};
        if (dimension == 0)
        {
            limits.bytes = 1;
            over.bytes   = 2;
        }
        if (dimension == 1)
        {
            limits.charge = 1;
            over.charge   = 2;
        }
        if (dimension == 2)
        {
            limits.entries = 1;
            over.entries   = 2;
        }
        bufferbudgetInit(&budget, limits);
        check(! bufferbudgetTryAcquire(&budget, over));
        check(budget.used.bytes == 0 && budget.used.charge == 0 && budget.used.entries == 0);
        check(bufferbudgetTryAcquire(&budget, (buffer_budget_cost_t) {1, 1, 1}));
        bufferbudgetRelease(&budget, budget.used);
    }
    bufferbudgetInit(&budget, (buffer_budget_cost_t) {2, 3, 1});
    check(bufferbudgetTryAcquire(&budget, (buffer_budget_cost_t) {2, 3, 1}));
    check(! bufferbudgetTryAcquire(&budget, (buffer_budget_cost_t) {1, 0, 0}));
    check(! bufferbudgetTryAcquire(&budget, (buffer_budget_cost_t) {0, 1, 0}));
    check(! bufferbudgetTryAcquire(&budget, (buffer_budget_cost_t) {0, 0, 1}));
    check(budget.used.bytes == 2 && budget.used.charge == 3 && budget.used.entries == 1);
    buffer_budget_reservation_t active = {&budget, {2, 3, 1}};
    bufferbudgetReservationSetBytes(&active, 0);
    check(budget.used.bytes == 0 && budget.used.charge == 3 && budget.used.entries == 1);
    bufferbudgetReservationRelease(&active);
    bufferbudgetReservationRelease(&active);
    bufferbudgetAssertEmpty(&budget);

    bufferbudgetInit(&budget, (buffer_budget_cost_t) {0, 0, 0});
    check(! bufferbudgetTryAcquire(&budget, (buffer_budget_cost_t) {0, 0, 1}));
    check(bufferbudgetTryAcquire(&budget, (buffer_budget_cost_t) {0, 0, 0}));
    bufferbudgetInit(&budget, (buffer_budget_cost_t) {SIZE_MAX, SIZE_MAX, SIZE_MAX});
    check(bufferbudgetTryAcquire(&budget, (buffer_budget_cost_t) {SIZE_MAX, SIZE_MAX - 1, SIZE_MAX - 2}));
    check(! bufferbudgetTryAcquire(&budget, (buffer_budget_cost_t) {1, 1, 1}));
    check(budget.used.charge == SIZE_MAX - 1 && budget.used.entries == SIZE_MAX - 2);
    check(bufferbudgetTryAcquire(&budget, (buffer_budget_cost_t) {0, 1, 2}));
    check(! bufferbudgetTryAcquire(&budget, (buffer_budget_cost_t) {0, 1, 0}));
    check(! bufferbudgetTryAcquire(&budget, (buffer_budget_cost_t) {0, 0, 1}));
    check(budget.used.bytes == SIZE_MAX && budget.used.charge == SIZE_MAX && budget.used.entries == SIZE_MAX);
    bufferbudgetRelease(&budget, budget.used);
    bufferbudgetAssertEmpty(&budget);

    sbuf_t *buf = sbufCreateWithPadding(64, 32);
    bufferbudgetInit(&budget, (buffer_budget_cost_t) {0, sbufGetQueueCharge(buf), 1});
    check(bufferbudgetTryReserve(&budget, buf, &active));
    buffer_budget_reservation_t competing = {0};
    check(! bufferbudgetTryReserve(&budget, buf, &competing));
    check(competing.budget == NULL && active.cost.entries == 1);
    bufferbudgetReservationRelease(&active);
    bufferbudgetAssertEmpty(&budget);
    sbufDestroy(buf);
    return 0;
}
