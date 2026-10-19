#include "rate_bucket.h"

static uint64_t ratebucketSaturatingAdd(uint64_t a, uint64_t b)
{
    return b > UINT64_MAX - a ? UINT64_MAX : a + b;
}

static uint64_t ratebucketSaturatingMultiply(uint64_t a, uint64_t b)
{
    return a != 0 && b > UINT64_MAX / a ? UINT64_MAX : a * b;
}

void ratebucketInit(rate_bucket_t *bucket, uint64_t initial_credit)
{
    *bucket = (rate_bucket_t) {.credit = initial_credit};
}

void ratebucketClamp(rate_bucket_t *bucket, uint64_t capacity)
{
    if (bucket->credit >= capacity)
    {
        bucket->credit    = capacity;
        bucket->remainder = 0;
    }
}

void ratebucketRefill(rate_bucket_t *bucket, uint64_t rate, uint64_t capacity, uint32_t step_ms, uint64_t now_ms)
{
    assert(step_ms > 0);
    ratebucketClamp(bucket, capacity);
    if (! bucket->has_clock)
    {
        bucket->last_refill_ms = now_ms;
        bucket->has_clock      = true;
        return;
    }
    if (now_ms <= bucket->last_refill_ms)
        return;

    uint64_t elapsed = now_ms - bucket->last_refill_ms;
    elapsed -= elapsed % step_ms;
    bucket->last_refill_ms += elapsed;
    if (elapsed == 0 || bucket->credit == capacity || rate == 0)
        return;

    /* rate * elapsed / 1000, without forming either unbounded product.
     * Every intermediate is capped against missing whole-byte credit. */
    uint64_t missing = capacity - bucket->credit;
    uint64_t seconds = elapsed / 1000;
    if (seconds != 0 && rate > (missing - 1) / seconds)
    {
        bucket->credit    = capacity;
        bucket->remainder = 0;
        return;
    }
    uint64_t earned = seconds * rate;
    uint64_t millis = elapsed % 1000;
    uint64_t whole  = rate / 1000;
    if (millis != 0 && whole > (missing - earned - 1) / millis)
    {
        bucket->credit    = capacity;
        bucket->remainder = 0;
        return;
    }
    earned += millis * whole;
    uint64_t fraction = millis * (rate % 1000) + bucket->remainder;
    uint64_t extra    = fraction / 1000;
    if (extra >= missing - earned)
    {
        bucket->credit    = capacity;
        bucket->remainder = 0;
        return;
    }
    bucket->credit += earned + extra;
    bucket->remainder = (uint16_t) (fraction % 1000);
}

uint64_t ratebucketAvailable(const rate_bucket_t *bucket)
{
    return bucket->credit;
}

uint64_t ratebucketGrant(rate_bucket_t *bucket, uint64_t requested, bool allow_partial)
{
    uint64_t grant = requested;
    if (grant > bucket->credit)
        grant = allow_partial ? bucket->credit : 0;
    bucket->credit -= grant;
    return grant;
}

uint64_t ratebucketRetryMs(const rate_bucket_t *bucket, uint64_t rate, uint32_t step_ms, uint64_t now_ms,
                           uint64_t requested)
{
    assert(step_ms > 0);
    if (bucket->credit >= requested)
        return 0;
    if (rate == 0)
        return UINT64_MAX;

    /* Decompose missing bytes by rate before converting to milliseconds. The
     * small remainder product is also decomposed to handle UINT64_MAX rates. */
    uint64_t missing = requested - bucket->credit;
    uint64_t seconds = missing / rate;
    uint64_t rem     = missing % rate;
    if (rem == 0 && seconds != 0)
    {
        --seconds;
        rem = rate;
    }
    uint64_t wait = ratebucketSaturatingMultiply(seconds, 1000);
    /* ceil((rem * 1000 - fraction) / rate). Binary search the bounded 0..1000
     * millisecond suffix using the same safe refill arithmetic. */
    uint64_t low = 0, high = 1000;
    while (low < high)
    {
        uint64_t middle = low + (high - low) / 2;
        uint64_t whole  = (rate / 1000) * middle;
        uint64_t part   = (rate % 1000) * middle + bucket->remainder;
        whole += part / 1000;
        if (whole >= rem)
            high = middle;
        else
            low = middle + 1;
    }
    wait = ratebucketSaturatingAdd(wait, low);
    if (wait == UINT64_MAX)
        return wait;
    uint64_t steps   = wait / step_ms + (wait % step_ms != 0);
    uint64_t rounded = ratebucketSaturatingMultiply(steps, step_ms);
    uint64_t phase =
        bucket->has_clock && now_ms > bucket->last_refill_ms ? (now_ms - bucket->last_refill_ms) % step_ms : 0;
    return rounded > phase ? rounded - phase : 1;
}
