#pragma once

#include <stdbool.h>
#include <stdint.h>

/* One independent process budget for each IP family's retained reassembly pbufs.
 * Reservations carry counts only. No protocol traversal or pbuf free occurs under protection. */
bool           wwLwipReassemblyReserve(unsigned family, uint16_t count);
void           wwLwipReassemblyRelease(unsigned family, uint16_t count);
uint16_t       wwLwipReassemblyUsage(unsigned family);
struct stats_ *wwLwipSharedStats(void);

void wwLwipReassemblyCleanup4(void);
void wwLwipReassemblyCleanup6(void);
