#include "tun_windows_receive_policy.h"
#include "wwapi.h"

// Focused, platform-neutral coverage for the Windows TUN oversized-receive drop
// policy. Generic rate-limited accounting has its own logger utility test.
//
// The release/recycle/queue-ownership behaviour of routineReadFromTun() (that the
// Wintun packet and the reserved buffer are each freed exactly once and that
// previously queued valid buffers are preserved) is exercised through the Windows
// test harness / manual runs, since fully mocking the Wintun reader would require
// a large production refactor.

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

// Case 1 and 2: a packet equal to the MTU is accepted; one byte larger is a drop.
static void testPacketSizeDecision(void)
{
    const uint16_t mtu = 1400;

    require(! tunWindowsReceivePacketExceedsMtu(mtu, 0), "zero-length packet flagged oversized");
    require(! tunWindowsReceivePacketExceedsMtu(mtu, (uint64_t) mtu - 1), "under-MTU packet flagged oversized");
    require(! tunWindowsReceivePacketExceedsMtu(mtu, mtu), "packet equal to MTU flagged oversized");
    require(tunWindowsReceivePacketExceedsMtu(mtu, (uint64_t) mtu + 1), "packet one byte over MTU not flagged");
    require(tunWindowsReceivePacketExceedsMtu(mtu, 0x400000), "large packet not flagged oversized");
}

/*
 * Wintun receive-error classification.
 *
 * Only an exhausted ring is recoverable. Everything else must be terminal so the
 * reader returns and the thread wrapper can publish FAILED and request the
 * orderly shutdown.
 */
static void testOnlyAnExhaustedRingIsRecoverable(void)
{
    require(tunWindowsClassifyReceiveError(kTunWintunErrorNoMoreItems) == kTunWindowsReceiveWaitForData,
            "ERROR_NO_MORE_ITEMS was not treated as a recoverable empty ring");

    // The two other errors WintunReceivePacket documents. Both mean the session
    // is finished, so neither may be retried.
    require(tunWindowsClassifyReceiveError(38UL) == kTunWindowsReceiveTerminal,
            "ERROR_HANDLE_EOF (adapter terminating) was not treated as terminal");
    require(tunWindowsClassifyReceiveError(13UL) == kTunWindowsReceiveTerminal,
            "ERROR_INVALID_DATA (corrupt ring) was not treated as terminal");
}

/*
 * Regression guard.
 *
 * ERROR_ENVVAR_NOT_FOUND used to be special-cased with an unbounded `continue`,
 * added when the reader still read GetLastError() *after* recycling its buffer -
 * so an unrelated env-var lookup on the recycle path could leave 203 behind and
 * be mistaken for a receive error. With the error now captured immediately after
 * the call, that source is gone and the value has no documented meaning here.
 * Retrying it forever is exactly the silent blackhole this policy exists to
 * prevent, so it must classify as terminal like any other unexpected error.
 */
static void testUndocumentedErrorsAreTerminal(void)
{
    enum
    {
        kErrorEnvvarNotFound = 203
    };

    require(tunWindowsClassifyReceiveError(kErrorEnvvarNotFound) == kTunWindowsReceiveTerminal,
            "ERROR_ENVVAR_NOT_FOUND is retried forever instead of failing the device");

    // An arbitrary unexpected error, and a NULL packet with no error recorded at
    // all: neither is a documented recoverable result, so both end the reader.
    require(tunWindowsClassifyReceiveError(1234UL) == kTunWindowsReceiveTerminal,
            "an arbitrary unexpected receive error was treated as recoverable");
    require(tunWindowsClassifyReceiveError(0UL) == kTunWindowsReceiveTerminal,
            "a failed receive that recorded no error was treated as recoverable");
    require(tunWindowsClassifyReceiveError(0xFFFFFFFFUL) == kTunWindowsReceiveTerminal,
            "a large unexpected receive error was treated as recoverable");

    // Neighbouring values must not be swallowed by an off-by-one in the compare.
    require(tunWindowsClassifyReceiveError(kTunWintunErrorNoMoreItems - 1) == kTunWindowsReceiveTerminal,
            "the value below ERROR_NO_MORE_ITEMS was treated as recoverable");
    require(tunWindowsClassifyReceiveError(kTunWintunErrorNoMoreItems + 1) == kTunWindowsReceiveTerminal,
            "the value above ERROR_NO_MORE_ITEMS was treated as recoverable");
}

int main(void)
{
    testOnlyAnExhaustedRingIsRecoverable();
    testUndocumentedErrorsAreTerminal();
    testPacketSizeDecision();
    return 0;
}
