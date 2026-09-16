#pragma once

#include "raw.h"

#if defined(OS_LINUX)

/* Production writer body exposed for deterministic syscall-failure tests. */
WTHREAD_ROUTINE(rawLinuxWriteRoutine);

/* Lifecycle-owner operations. Stop the writer before removing its exemption. */
bool rawLinuxNotrackInstall(raw_device_t *rdev);
bool rawLinuxNotrackRemove(raw_device_t *rdev);

/* Selection inspects IPv4 iptables-save and ip -4 rule show snapshots. */
bool rawLinuxSelectNotrackMark(const char *iptables_rules, const char *routing_rules, uint32_t *selected);

#endif
