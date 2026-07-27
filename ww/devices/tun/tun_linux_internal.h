#pragma once

#include "devices/device_reader_session.h"
#include "shiftbuffer.h"
#include "tun.h"

#if defined(OS_LINUX)

/* Test-only observations of Linux TUN lifetime-owned resources. */
device_reader_session_t *tunLinuxReaderSession(tun_device_t *tdev);
buffer_pool_t           *tunLinuxWriterBufferPool(tun_device_t *tdev);

/* Test-only: substitute the reader body so a routine that returns on its own can
 * be exercised without a real device error. */
void tunLinuxSetReaderRoutine(tun_device_t *tdev, wthread_routine routine);

#endif
