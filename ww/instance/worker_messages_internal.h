#pragma once

/*
 * Internal storage contract shared by worker-message-owned record types.
 * Callers acquire only records which fit the pool's explicit union geometry
 * and must return every acquired record exactly once.
 * Checkout and return use the current event worker's local cache while it
 * exists, otherwise the shared master. Records carry no source-pool pointer;
 * settlement may migrate them to another worker or outlive the source cache.
 */

#include "worker_messages.h"

WW_MUST_USE void *workerMessagePoolAcquire(size_t record_size);
void              workerMessagePoolRelease(void *record);

#ifdef WW_WORKER_MESSAGE_TEST_SEAM
size_t workerMessagesTestQueueCapacity(worker_t *worker);
#endif
