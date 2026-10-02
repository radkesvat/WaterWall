#pragma once



void increaseFileLimit(void);

/* Best-effort Linux startup increase to a finite pipe-user-pages-hard value,
 * or 512 MiB in system pages when the hard limit is unlimited.
 * This changes the live system-wide soft-limit setting, never the hard limit. */
void tryIncreasePipeLimit(void);

/* Best-effort native Linux TCP/socket tuning: TCP buffer maxima stay at 128 MiB,
 * while socket ceilings and backlogs follow the RAM profile.
 * Each setting is attempted independently; failures never fail startup. */
void tryTuneTcp(unsigned int ram_profile);

void tryEnableBbr(void);
