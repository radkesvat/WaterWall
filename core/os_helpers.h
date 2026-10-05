#pragma once

#include <stdbool.h>

void increaseFileLimit(void);

/* Best-effort Linux startup increase to a finite pipe-user-pages-hard value,
 * or 512 MiB in system pages when the hard limit is unlimited.
 * This changes the live system-wide soft-limit setting, never the hard limit. */
void tryIncreasePipeLimit(void);

/* Best-effort native Linux startup tuning: when splice is enabled, raise live
 * tcp_mem to 3:4:6 with pressure at one quarter of host RAM in system pages,
 * unless any threshold would decrease. Fixed 128 MiB socket/TCP buffer ceilings
 * apply even with splice disabled and remain independent of the RAM profile.
 * Failures never fail startup or prevent other settings. */
void tryTuneTcp(bool splice_enabled);

void tryEnableBbr(void);
