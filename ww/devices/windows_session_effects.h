#pragma once
#include <stdbool.h>
#include <stdint.h>

/* These Windows SDK headers have a required dependency order. */
// clang-format off
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
// clang-format on

/* Identifies the adapter/driver inventory layout shared with recovery. */
#define WW_SESSION_EFFECT_MAGIC UINT64_C(0x5757414441505452)
#define WW_SESSION_ADAPTER_MAX  512

typedef struct windows_session_adapter_s
{
    /* 0 unused, 1 creation in progress/unverified, 2 exact GUID published. */
    volatile LONG state;
    GUID          guid;
} windows_session_adapter_t;
typedef struct windows_session_effects_s
{
    uint64_t                  magic;
    LONG                      driver_residue;
    windows_session_adapter_t adapters[WW_SESSION_ADAPTER_MAX];
} windows_session_effects_t;

/* Startup owner attaches once. Mapping is retained through process exit so
 * adapter creation never borrows runtime or launcher callback storage. */
bool windowsSessionEffectsAttach(uintptr_t mapping);
bool windowsSessionAdapterBegin(unsigned *slot);
bool windowsSessionAdapterConfirm(unsigned slot, const NET_LUID *luid);

void windowsSessionDriverUnsettled(void);
