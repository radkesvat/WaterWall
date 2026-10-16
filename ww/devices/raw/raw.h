#pragma once

#include "shiftbuffer.h"
#include "wlibc.h"

typedef struct raw_device_s raw_device_t;

/* The caller owns a live handle until rawdeviceDestroy(). BringDown waits for
 * admitted native output, settles pending I/O and discards queued ownership.
 * RequestStop only closes admission. Create/BringUp run on an event worker before
 * publication. The lifecycle owner serializes stop, wait and destruction;
 * destruction follows producer quiescence.
 * IsUp is a snapshot, not a lifetime reference or permission to race destruction. */

bool rawdeviceIsUp(const raw_device_t *rdev);
bool rawdeviceBringUp(raw_device_t *rdev);
void rawdeviceRequestStop(raw_device_t *rdev);
bool rawdeviceBringDown(raw_device_t *rdev);
/* Called from an event worker with a live handle. The buffer must contain at
 * least an IPv4 base header; header-only IPv4 packets are allowed. True transfers
 * the buffer to the device queue, not necessarily to the network. False leaves
 * it with the caller. Output is deferred on that worker; no native send occurs
 * inside this call. Order is FIFO per worker, without a total cross-worker order. */
bool rawdeviceWrite(raw_device_t *rdev, sbuf_t *buf);

raw_device_t *rawdeviceCreate(const char *name, uint32_t mark, bool bypass_conntrack, void *userdata);

void rawdeviceDestroy(raw_device_t *rdev);
