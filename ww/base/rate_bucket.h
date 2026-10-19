#pragma once

#include "wlibc.h"

/* Pure arithmetic. The caller supplies synchronization, clock and policy.
 * Credit is whole bytes plus thousandths of a byte; time zero is valid. */
typedef struct rate_bucket_s
{
    uint64_t credit;
    uint64_t last_refill_ms;
    uint16_t remainder;
    bool     has_clock;
} rate_bucket_t;

void     ratebucketInit(rate_bucket_t *bucket, uint64_t initial_credit);
void     ratebucketClamp(rate_bucket_t *bucket, uint64_t capacity);
void     ratebucketRefill(rate_bucket_t *bucket, uint64_t rate, uint64_t capacity, uint32_t step_ms, uint64_t now_ms);
uint64_t ratebucketAvailable(const rate_bucket_t *bucket);
uint64_t ratebucketGrant(rate_bucket_t *bucket, uint64_t requested, bool allow_partial);
/* Time to requested whole-byte credit, rounded up to the provider's recharge
 * step. UINT64_MAX denotes an unrepresentable wait or a zero-rate policy. */
uint64_t ratebucketRetryMs(const rate_bucket_t *bucket, uint64_t rate, uint32_t step_ms, uint64_t now_ms,
                           uint64_t requested);
