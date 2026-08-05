#pragma once

#include <stdbool.h>
#include <stdint.h>

// Platform-neutral Wintun receive policy. Aggregate warning accounting is
// provided by loggers/log_rate_limiter.h rather than being device-specific.

/*
 * Wintun receive-error policy.
 *
 * WintunReceivePacket() lists three possible failures (ww/vendor/wintun/wintun.h):
 *
 *   ERROR_NO_MORE_ITEMS   the ring is exhausted   -> recoverable, wait for data
 *   ERROR_HANDLE_EOF      the adapter is terminating
 *   ERROR_INVALID_DATA    the ring is corrupt
 *
 * Only the first is recoverable. Every other value - documented or not - means
 * the session will not produce packets again, so the reader must leave its loop
 * and let tundeviceNoteUnexpectedThreadExit() publish the failure. Treating an
 * unrecognised error as recoverable is what produces the silent blackhole: the
 * reader spins forever while the device is still advertised as up.
 *
 * The numeric value is restated here because this header is included before
 * <windows.h> and is compiled on non-Windows hosts for unit tests. tun_windows.c
 * static-asserts it against the real Win32 macro, so the two cannot drift.
 */
enum
{
    kTunWintunErrorNoMoreItems = 259 // ERROR_NO_MORE_ITEMS
};

typedef enum tun_windows_receive_action_e
{
    kTunWindowsReceiveWaitForData = 0, // Ring empty; the session is healthy.
    kTunWindowsReceiveTerminal         // The session is lost; leave the reader loop.
} tun_windows_receive_action_t;

// Classifies the last error reported by a failed WintunReceivePacket() call. The
// caller must read that error immediately after the call: releasing the reserved
// buffer first runs arbitrary code that can overwrite the thread's last error.
static inline tun_windows_receive_action_t tunWindowsClassifyReceiveError(unsigned long last_error)
{
    if (last_error == (unsigned long) kTunWintunErrorNoMoreItems)
    {
        return kTunWindowsReceiveWaitForData;
    }
    return kTunWindowsReceiveTerminal;
}

// Classifies a received packet against the configured MTU.
static inline bool tunWindowsReceivePacketExceedsMtu(uint16_t mtu, uint64_t packet_size)
{
    return packet_size > (uint64_t) mtu;
}
