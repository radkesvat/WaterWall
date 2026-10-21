#pragma once

#include <stdbool.h>
#include <stdint.h>

void increaseFileLimit(void);

/* Process-wide splice capacity budget: profile ceiling, capped by one fifth of
 * effective maximum RAM when known, rounded down to whole payload-limit pipes.
 * A zero effective_total_bytes means that RAM detection is unavailable. */
uint64_t spliceCapacityLimit(uint32_t ram_profile, uint64_t effective_total_bytes);

/* Best-effort Linux startup increase to the configured splice budget in system
 * pages, capped by pipe-user-pages-hard when that hard limit is finite.
 * This changes the live system-wide soft-limit setting, never the hard limit.
 * capacity_limit must not exceed SPLICE_TOTAL_SIZE_LIMIT; zero skips tuning. */
void tryIncreasePipeLimit(uint64_t capacity_limit);

/* Splice pipe count ceiling: at most one quarter of the remaining soft
 * descriptor allowance may belong to pipe pairs, including the /proc/self/fd
 * scan descriptor conservatively, capped by the supplied capacity budget.
 * capacity_limit must not exceed SPLICE_TOTAL_SIZE_LIMIT.
 * Returns zero when unavailable/unsupported. */
uint32_t splicePipeCountLimit(uint64_t capacity_limit);

/* Best-effort native Linux startup tuning: when splice is enabled, raise live
 * tcp_mem to 3:4:6 with pressure at one quarter of host RAM in system pages,
 * unless any threshold would decrease. Fixed 128 MiB socket/TCP buffer ceilings
 * apply even with splice disabled and remain independent of the RAM profile.
 * Failures never fail startup or prevent other settings. */
void tryTuneTcp(bool splice_enabled);

void tryEnableBbr(void);
