#pragma once

/* Application startup owner only. Hooks run on the main thread outside the
 * shutdown-controller lock; ordinary runtime callers retain runMainThread(). */
void globalstateRunMainThreadWithStartupHooks(void (*before_commit)(void), void (*after_publication)(void));
