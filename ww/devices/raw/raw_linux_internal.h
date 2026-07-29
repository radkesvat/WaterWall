#pragma once

#include "raw.h"

#if defined(OS_LINUX)

/* Production writer body exposed for deterministic syscall-failure tests. */
WTHREAD_ROUTINE(rawLinuxWriteRoutine);

#endif
