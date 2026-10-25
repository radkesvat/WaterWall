#pragma once

#include "capture.h"

/* Exclusive lifecycle ownership prepares inactive readers before installing
 * rules. Normal activation is queued after packet Init on each owner worker.
 * After CloseWait all native queues belong to the coordinator again. */
void captureReaderOpen(capture_device_t *device);
bool captureReaderStart(capture_device_t *device);
void captureReaderCloseRequest(capture_device_t *device);
void captureReaderCloseWait(capture_device_t *device);
void captureReaderDestroy(capture_device_t *device);
void captureReaderCapacityReady(void *context);
/* Coordinator-only, bounded, nonblocking service during commands. Active startup
 * queues capture into the session FIFO; inactive/stopped queues send NF_ACCEPT. */
void captureReaderService(void *context);
bool captureReaderDrain(capture_device_t *device);
