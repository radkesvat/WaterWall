#pragma once

#include <stdbool.h>
#include <stdint.h>

void increaseFileLimit(void);

/* Best-effort Linux startup increase to the configured splice budget in system
 * pages, capped by pipe-user-pages-hard when that hard limit is finite.
 * This changes the live system-wide soft-limit setting, never the hard limit. */
void tryIncreasePipeLimit(void);

/* Startup splice pipe count ceiling: at most one quarter of the remaining soft
 * descriptor allowance may belong to pipe pairs, including the /proc/self/fd
 * scan descriptor conservatively. Returns zero when unavailable/unsupported. */
uint32_t splicePipeCountLimit(void);

/* Best-effort native Linux startup tuning: when splice is enabled, raise live
 * tcp_mem to 3:4:6 with pressure at one quarter of host RAM in system pages,
 * unless any threshold would decrease. Fixed 128 MiB socket/TCP buffer ceilings
 * apply even with splice disabled and remain independent of the RAM profile.
 * Failures never fail startup or prevent other settings. */
void tryTuneTcp(bool splice_enabled);

void tryEnableBbr(void);
