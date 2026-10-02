/*
 * Covers: raw windows send policy; the explicit inputs, callbacks and expected results below define this
 * suite.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Cases: testDocumentedPacketErrorsAreLocal, testPersistentAndUnknownErrorsAreTerminal
 * Checks: Assertion labels include: ERROR_DATA_NOT_ACCEPTED was not classified as a packet-local discard;
 * ERROR_HOST_UNREACHABLE was not classified as a packet-local discard; WinDivert's persistent
 * ERROR_RETRY compatibility failure was retried; ERROR_INVALID_HANDLE was not classified as terminal
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.raw_windows_send_policy_unit
 */
#include "raw_windows_send_policy.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)
#include "wwapi.h"


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
    testCaseSet("raw_windows_send_policy_test");
    testDocumentedPacketErrorsAreLocal();
    testPersistentAndUnknownErrorsAreTerminal();
    return 0;
}
