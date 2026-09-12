#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Application-owned, Windows-only lifecycle capabilities. Events are manual-reset
 * capabilities; the launcher also has a private named stop event for recovery.
 * Start consumes the supplied inherited handles,
 * including on failure; the parser itself never owns handles. */
bool      waterwallLifecycleStart(uintptr_t stop_event, uintptr_t ready_event, uintptr_t controller_process);
void      waterwallLifecycleCheckpoint(void);
void      waterwallLifecyclePublishReady(void);
void      waterwallLifecycleDestroy(void);
uintptr_t waterwallLifecycleStopEvent(void);

#ifdef WATERWALL_LIFECYCLE_TEST_HOOKS
/* One-shot setup failures; present only in the focused fixture. */
void waterwallLifecycleTestFailSetup(bool thread_creation);
#endif
