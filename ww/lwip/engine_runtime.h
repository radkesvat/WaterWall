#pragma once

#include "engine.h"

/* Startup publication precedes all normal worker work. No eager engine creation. */
bool wwLwipRuntimeInitialize(uint8_t workers);
void wwLwipRuntimeFinalize(void);
/* Foreign/unregistered calls, closed admission and allocation refusal return NULL. */
ww_lwip_engine_t *wwLwipRuntimeGet(uint8_t owner);
/* Owner-only lifecycle hooks; an unused slot is valid and idempotent. */
void wwLwipRuntimeQuiesceWorker(uint8_t owner);
void wwLwipRuntimeDestroyWorker(uint8_t owner);

#if defined(WW_LWIP_TEST_SEAM)
/* Startup-only fault seam; no branch exists in production builds. */
void wwLwipRuntimeTestFailSlots(bool fail);
#endif
