#pragma once



void increaseFileLimit(void);

/* Best-effort Linux startup increase to a finite pipe-user-pages-hard value,
 * or 512 MiB in system pages when the hard limit is unlimited.
 * This changes the live system-wide soft-limit setting, never the hard limit. */
void tryIncreasePipeLimit(void);

void tryEnableBbr(void);
