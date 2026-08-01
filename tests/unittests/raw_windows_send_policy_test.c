#include "raw_windows_send_policy.h"
#include "wwapi.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void testDocumentedPacketErrorsAreLocal(void)
{
    require(rawWindowsClassifySendError(kRawWindowsErrorDataNotAccepted) == kRawWindowsSendDiscardPacket,
            "ERROR_DATA_NOT_ACCEPTED was not classified as a packet-local discard");
    require(rawWindowsClassifySendError(kRawWindowsErrorHostUnreachable) == kRawWindowsSendDiscardPacket,
            "ERROR_HOST_UNREACHABLE was not classified as a packet-local discard");
}

static void testPersistentAndUnknownErrorsAreTerminal(void)
{
    require(rawWindowsClassifySendError(kRawWindowsErrorRetry) == kRawWindowsSendTerminal,
            "WinDivert's persistent ERROR_RETRY compatibility failure was retried");
    require(rawWindowsClassifySendError(6UL) == kRawWindowsSendTerminal,
            "ERROR_INVALID_HANDLE was not classified as terminal");
    require(rawWindowsClassifySendError(0UL) == kRawWindowsSendTerminal,
            "a failed send with no recorded error was not classified as terminal");
    require(rawWindowsClassifySendError(0xFFFFFFFFUL) == kRawWindowsSendTerminal,
            "an unknown WinDivertSend error was not classified as terminal");
}

int main(void)
{
    testDocumentedPacketErrorsAreLocal();
    testPersistentAndUnknownErrorsAreTerminal();
    return 0;
}
