#pragma once

#include "devices/device_lifetime.h"
#include "shiftbuffer.h"
#include "tun.h"

#if defined(OS_LINUX)

/*
 * Linux TUN queued-message seams. These are exposed only so the focused
 * lifetime regression test can post, deliver, and clean up real production
 * messages without opening a privileged TUN device.
 */
void distributePacketPayloads(tun_device_t *tdev, uint8_t target_wid, sbuf_t **buf, unsigned int queued_count);
void localThreadMessageReceived(void *worker, void *arg1, void *arg2, void *arg3);
void cleanupPostedTunMessage(void *arg1, void *arg2, void *arg3);

/* Test-only observations of Linux TUN lifetime-owned resources. */
device_reader_session_t *tunLinuxReaderSession(tun_device_t *tdev);
buffer_pool_t           *tunLinuxWriterBufferPool(tun_device_t *tdev);

#endif
