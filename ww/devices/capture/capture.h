#pragma once

#include "devices/capture/capture_protocol_filter.h"
#include "devices/device_fragment_policy.h"
#include "shiftbuffer.h"
#include "wlibc.h"
#include "worker.h"

typedef struct capture_device_s capture_device_t;
/* Called on the selected event worker. The callback consumes buf; the device
 * and userdata remain live through the call under the reader delivery gate. */
typedef void (*CaptureReadEventHandle)(capture_device_t *cdev, void *userdata, sbuf_t *buf, wid_t tid);

/* All calls require a live handle. RequestStop only signals the reader; BringDown
 * joins it and releases active capture resources. IsUp retains the published
 * compatibility status (a relaxed atomic load), including startup/stop timing.
 * Create/BringUp run on an event worker before publication. The lifecycle owner
 * serializes stop, join and destruction; destruction follows producer quiescence.
 * IsUp is a snapshot, not a lifetime reference or permission to race destruction. */
bool capturedeviceIsUp(const capture_device_t *cdev);
bool caputredeviceBringUp(capture_device_t *cdev);
bool capturedeviceRequestStop(capture_device_t *cdev);
bool caputredeviceBringDown(capture_device_t *cdev);

/* skip_sysctl suppresses only optional Linux kernel tuning. bypass_conntrack
 * controls Linux NOTRACK rules; NFQUEUE capture remains enabled either way. */
capture_device_t *caputredeviceCreate(const char *name, const ipmask_t *capture_ranges, uint32_t capture_range_count,
                                      bool skip_sysctl, bool bypass_conntrack,
                                      const capture_protocol_filter_t *protocol_filter, void *userdata,
                                      CaptureReadEventHandle cb, device_fragment_policy_t fragment_policy);

void capturedeviceDestroy(capture_device_t *cdev);
