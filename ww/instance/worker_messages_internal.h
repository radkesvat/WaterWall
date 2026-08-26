#pragma once

/*
 * Internal storage contract shared by worker-message-owned record types.
 * Callers acquire only records which fit the pool's explicit union geometry
 * and must return every acquired record exactly once.
 */

#include "worker_messages.h"

WW_MUST_USE void *workerMessagePoolAcquire(size_t record_size);
void              workerMessagePoolRelease(void *record);
