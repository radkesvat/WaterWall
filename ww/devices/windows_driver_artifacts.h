#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <windows.h>

/* Serialized process startup/teardown only. These are the three embedded
 * artifacts, not a public path or plugin-loading interface. */
typedef enum windows_driver_artifact_e
{
    kWindowsDriverWintun = 0,
    kWindowsDriverWinDivertDll,
    kWindowsDriverWinDivertSys,
    kWindowsDriverArtifactCount
} windows_driver_artifact_t;

/* Success borrows the immutable path until Release, after the module/user is
 * gone. A repeated Prepare for the same pinned embedded bytes is idempotent. */
bool windowsDriverArtifactPrepare(windows_driver_artifact_t artifact, const unsigned char *bytes, size_t length,
                                  const wchar_t **path);
bool windowsDriverArtifactRelease(windows_driver_artifact_t artifact);
/* Retry only failed/unreferenced transactions; never release an active module's files. */
void windowsDriverArtifactsShutdown(void);
