#pragma once

#include "engine.h"

/* Startup publication precedes all normal worker work. No eager engine creation. */
void wwLwipRuntimeInitialize(uint8_t workers);
void wwLwipRuntimeFinalize(void);
/* Foreign/unregistered calls, unavailable runtime and closed admission return NULL. */
ww_lwip_engine_t *wwLwipRuntimeGet(uint8_t owner);
/* Begin a bounded synchronous receive batch only if this worker already has an
 * engine. Pair a non-NULL result with wwLwipEngineEndAckBatch() before yielding.
 * Device-only traffic must not create an otherwise unused stack. */
ww_lwip_engine_t *wwLwipRuntimeBeginAckBatch(uint8_t owner);
/* Owner-only lifecycle hooks; an unused slot is valid and idempotent. */
void wwLwipRuntimeQuiesceWorker(uint8_t owner);
void wwLwipRuntimeDestroyWorker(uint8_t owner);
