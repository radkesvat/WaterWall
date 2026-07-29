#pragma once

/*
 * WinDivert send-error policy, kept independent of windows.h so it can be
 * unit-tested on non-Windows hosts. raw_windows.c static-asserts these values
 * against the real Win32 constants.
 *
 * ERROR_DATA_NOT_ACCEPTED rejects one malformed (or otherwise unacceptable)
 * packet. ERROR_HOST_UNREACHABLE is WinDivert's per-packet loop-protection
 * failure. Everything else, including ERROR_RETRY (which WinDivert documents as
 * a persistent security-software compatibility problem), ends the writer.
 */
enum
{
    kRawWindowsErrorDataNotAccepted = 592,
    kRawWindowsErrorHostUnreachable = 1232,
    kRawWindowsErrorRetry           = 1237
};

typedef enum raw_windows_send_action_e
{
    kRawWindowsSendDiscardPacket = 0,
    kRawWindowsSendTerminal
} raw_windows_send_action_t;

static inline raw_windows_send_action_t rawWindowsClassifySendError(unsigned long last_error)
{
    if (last_error == (unsigned long) kRawWindowsErrorDataNotAccepted ||
        last_error == (unsigned long) kRawWindowsErrorHostUnreachable)
    {
        return kRawWindowsSendDiscardPacket;
    }
    return kRawWindowsSendTerminal;
}
