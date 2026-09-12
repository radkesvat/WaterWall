#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <windows.h>

typedef enum tun_windows_dns_result_e
{
    kTunWindowsDnsSuccess,
    kTunWindowsDnsCancelled,
    kTunWindowsDnsFailed
} tun_windows_dns_result_e;

/* Main startup owner lends this validated manual-reset event until all DNS
 * operations finish. This is explicit cancellation, not a process-phase query. */
void tunWindowsDnsSetStartupStopEvent(HANDLE stop_event);

/* Only typed IPv4 DNS operations on a newly created, exclusively owned adapter.
 * may_have_changed reports a started helper, even on failure. The owner retains
 * those effects until Clear succeeds. Clear has a separate, uncancelled budget. */
tun_windows_dns_result_e tunWindowsDnsSet(const wchar_t *adapter, HANDLE ownership, const char *const *servers,
                                          size_t count, HANDLE device_stop, bool *may_have_changed);
bool                     tunWindowsDnsClear(const wchar_t *adapter, HANDLE ownership);
/* Permanently closes Set/Clear helper admission before final bounded settlement.
 * Repeated shutdown may settle an existing pending helper, but never starts one. */
bool tunWindowsDnsShutdown(void);

struct tun_device_s;
bool tundeviceWindowsDnsWasCancelled(const struct tun_device_s *device);
bool tundeviceWindowsDnsNeedsCleanup(const struct tun_device_s *device);
