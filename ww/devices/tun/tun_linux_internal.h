#pragma once

#include "devices/device_reader_session.h"
#include "devices/tun/tun_lifecycle.h"
#include "devices/tun/tun_writer.h"
#include "shiftbuffer.h"
#include "tun.h"

#if defined(OS_LINUX)

/* Command adapter seam: runs an argv directly without opening a TUN device. */
int tunLinuxRunCommandForTest(const char *command_name, const char *const argv[]);

/* Test-only observations of Linux TUN lifetime-owned resources. */
device_reader_session_t *tunLinuxReaderSession(tun_device_t *tdev);
tun_writer_t            *tunLinuxWriter(tun_device_t *tdev);

/* Test-only: substitute the reader body so a routine that returns on its own can
 * be exercised without a real device error. */
void tunLinuxSetReaderRoutine(tun_device_t *tdev, wthread_routine routine);

/* Test-only lifecycle observation for exact rollback-state assertions. */
tun_lifecycle_state_t tunLinuxLifecycleState(const tun_device_t *tdev);

#endif
