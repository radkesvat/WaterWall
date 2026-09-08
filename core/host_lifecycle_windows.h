#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Application-owned, Windows-only lifecycle capabilities. Both events are fresh
 * unnamed manual-reset events. Start consumes the supplied inherited handles,
 * including on failure; the parser itself never owns handles. */
bool      waterwallHostLifecycleStart(uintptr_t stop_event, uintptr_t ready_event);
void      waterwallHostLifecycleCheckpoint(void);
void      waterwallHostLifecyclePublishReady(void);
void      waterwallHostLifecycleDestroy(void);
uintptr_t waterwallHostLifecycleStopEvent(void);

#ifdef WATERWALL_HOST_LIFECYCLE_TEST_HOOKS
/* One-shot setup failures; present only in the focused fixture. */
void waterwallHostLifecycleTestFailSetup(bool thread_creation);
#endif
