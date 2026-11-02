/*
 * Covers: Transactional byte and retained-allocation charge limits for buffer-budget admission.
 * Setup: Inline deterministic costs and real padded/empty sbufs; no workers or runtime fixture.
 * Cases: Independent dimensions, exact bounds, zero limits, SIZE_MAX overflow, reservation byte updates,
 * competing reservations, more than 1024 empty buffers and repeated release.
 * Checks: Refusal preserves usage, reservation updates retain charge, empty buffers remain bounded by
 * storage charge and every accepted cost settles to an empty budget.
 * CTest: waterwall.buffer_budget_unit
 */
#include "buffer_budget.h"

#include "test_assert.h"

#include <stdio.h>
#include <stdlib.h>

#define check(condition) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, "buffer budget contract failed")

static void testEmptyBufferReservations(void)
{
    enum
    {
        kRetainedBuffers = 1025
    };
    sbuf_t                     *buffers[kRetainedBuffers];
    buffer_budget_reservation_t reservations[kRetainedBuffers] = {0};
    buffer_budget_t             budget;
    sbuf_t                     *extra  = sbufCreate(0);
    const size_t                charge = sbufGetQueueCharge(extra);
    check(charge > 0 && sbufGetLength(extra) == 0);
    bufferbudgetInit(&budget, (buffer_budget_cost_t) {0, kRetainedBuffers * charge});
    for (size_t i = 0; i < kRetainedBuffers; ++i)
    {
        buffers[i] = sbufCreate(0);
        check(bufferbudgetTryReserve(&budget, buffers[i], &reservations[i]));
    }
    check(budget.used.bytes == 0 && budget.used.charge == budget.limits.charge);
    buffer_budget_reservation_t competing = {0};
    check(! bufferbudgetTryReserve(&budget, extra, &competing) && competing.budget == NULL);
    check(budget.used.bytes == 0 && budget.used.charge == kRetainedBuffers * charge);
    bufferbudgetReservationRelease(&reservations[0]);
    check(bufferbudgetTryReserve(&budget, extra, &competing));
    bufferbudgetReservationRelease(&competing);
    sbufDestroy(extra);
    for (size_t i = 0; i < kRetainedBuffers; ++i)
    {
        bufferbudgetReservationRelease(&reservations[i]);
        sbufDestroy(buffers[i]);
    }
    bufferbudgetAssertEmpty(&budget);
}

int main(void)
{
    testCaseSet("buffer_budget_test");
    buffer_budget_t budget;
    for (unsigned dimension = 0; dimension < 2; ++dimension)
    {
        buffer_budget_cost_t limits = {SIZE_MAX, SIZE_MAX};
        buffer_budget_cost_t over   = {1, 1};
        if (dimension == 0)
        {
            limits.bytes = 1;
            over.bytes   = 2;
        }
        else
        {
            limits.charge = 1;
            over.charge   = 2;
        }
        bufferbudgetInit(&budget, limits);
        check(! bufferbudgetTryAcquire(&budget, over));
        check(budget.used.bytes == 0 && budget.used.charge == 0);
        check(bufferbudgetTryAcquire(&budget, (buffer_budget_cost_t) {1, 1}));
        bufferbudgetRelease(&budget, budget.used);
    }
    bufferbudgetInit(&budget, (buffer_budget_cost_t) {2, 3});
    check(bufferbudgetTryAcquire(&budget, (buffer_budget_cost_t) {2, 3}));
    check(! bufferbudgetTryAcquire(&budget, (buffer_budget_cost_t) {1, 0}));
    check(! bufferbudgetTryAcquire(&budget, (buffer_budget_cost_t) {0, 1}));
    check(budget.used.bytes == 2 && budget.used.charge == 3);
    buffer_budget_reservation_t active = {&budget, {2, 3}};
    bufferbudgetReservationSetBytes(&active, 0);
    check(budget.used.bytes == 0 && budget.used.charge == 3);
    bufferbudgetReservationRelease(&active);
    bufferbudgetReservationRelease(&active);
    bufferbudgetAssertEmpty(&budget);

    bufferbudgetInit(&budget, (buffer_budget_cost_t) {0, 0});
    check(! bufferbudgetTryAcquire(&budget, (buffer_budget_cost_t) {0, 1}));
    check(bufferbudgetTryAcquire(&budget, (buffer_budget_cost_t) {0, 0}));
    bufferbudgetInit(&budget, (buffer_budget_cost_t) {SIZE_MAX, SIZE_MAX});
    check(bufferbudgetTryAcquire(&budget, (buffer_budget_cost_t) {SIZE_MAX, SIZE_MAX - 1}));
    check(! bufferbudgetTryAcquire(&budget, (buffer_budget_cost_t) {1, 1}));
    check(budget.used.charge == SIZE_MAX - 1);
    check(bufferbudgetTryAcquire(&budget, (buffer_budget_cost_t) {0, 1}));
    check(! bufferbudgetTryAcquire(&budget, (buffer_budget_cost_t) {0, 1}));
    check(budget.used.bytes == SIZE_MAX && budget.used.charge == SIZE_MAX);
    bufferbudgetRelease(&budget, budget.used);
    bufferbudgetAssertEmpty(&budget);

    sbuf_t *buf = sbufCreateWithPadding(64, 32);
    bufferbudgetInit(&budget, (buffer_budget_cost_t) {0, sbufGetQueueCharge(buf)});
    check(bufferbudgetTryReserve(&budget, buf, &active));
    buffer_budget_reservation_t competing = {0};
    check(! bufferbudgetTryReserve(&budget, buf, &competing));
    check(competing.budget == NULL && active.cost.charge == sbufGetQueueCharge(buf));
    bufferbudgetReservationRelease(&active);
    bufferbudgetAssertEmpty(&budget);
    sbufDestroy(buf);
    testEmptyBufferReservations();
    return 0;
}
