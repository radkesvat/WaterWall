#pragma once

#include <stdbool.h>
#include <windows.h>

#define TUN_WINDOWS_OWNERSHIP_TAG_CAPACITY 80

typedef struct tun_windows_ownership_s
{
    HANDLE  lease;
    wchar_t tag[TUN_WINDOWS_OWNERSHIP_TAG_CAPACITY];
} tun_windows_ownership_t;

/* Constructor ownership, before egress-interface selection or socket setup. */
bool tunWindowsOwnershipPrepare(const char *name, tun_windows_ownership_t *ownership);

/* One logical device-name, case-insensitive, across Windows sessions. The
 * runtime retains the lease until device destruction. DNS helpers inherit a
 * reduced duplicate, so parent death cannot release their ownership early. */
HANDLE tunWindowsOwnershipAcquire(const wchar_t *name, wchar_t tag[TUN_WINDOWS_OWNERSHIP_TAG_CAPACITY]);

/* Requires the lease. Removes only present devices carrying this exact creation
 * tag and Wintun hardware identity. Phantom registry residue is not a blocker. */
bool tunWindowsOwnershipReconcile(const wchar_t *tag);

/* Explicit inheritance of the lease only, with absent standard handles and a
 * caller-provided environment. The caller owns the returned process/thread. */
bool tunWindowsOwnershipStartHelper(HANDLE lease, const wchar_t *executable, wchar_t *command, void *environment,
                                    const wchar_t *directory, PROCESS_INFORMATION *child);
