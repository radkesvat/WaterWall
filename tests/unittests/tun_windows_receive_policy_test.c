#include "tun_windows_receive_policy.h"

#include <stdio.h>
#include <stdlib.h>

// Focused, platform-neutral coverage for the Windows TUN oversized-receive drop
// policy: the packet-size decision and the rate-limited discard accounting state
// machine. Time is injected via explicit now_ms values so the test never sleeps.
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

// The first discard only arms the report clock; it never emits a per-packet log.
static void testFirstDiscardIsSilentButCounted(void)
{
    tun_oversized_read_discard_stats_t  stats  = {0};
    tun_oversized_read_discard_report_t report = tunWindowsAccountOversizedReadDiscard(&stats, 1000);

    require(! report.should_log, "first discard emitted a warning");
    require(stats.total == 1, "first discard did not count lifetime total");
    require(stats.suppressed == 1, "first discard did not count suppressed");
    require(stats.last_report_ms == 1000, "first discard did not arm the report clock");
}

// Case 7: repeated oversized packets inside one second produce a single aggregate
// reporting window rather than one warning per packet.
static void testRepeatedDiscardsAggregateIntoOneWindow(void)
{
    tun_oversized_read_discard_stats_t stats = {0};

    require(! tunWindowsAccountOversizedReadDiscard(&stats, 1000).should_log, "arming discard logged");

    for (unsigned long long t = 1100; t < 2000; t += 100)
    {
        require(! tunWindowsAccountOversizedReadDiscard(&stats, t).should_log,
                "a within-window discard produced a per-packet warning");
    }
    require(stats.suppressed == 10, "within-window discards were not accumulated");

    tun_oversized_read_discard_report_t report = tunWindowsAccountOversizedReadDiscard(&stats, 2000);
    require(report.should_log, "interval boundary did not emit an aggregate warning");
    require(report.discarded == 11, "aggregate warning miscounted discards");
    require(report.elapsed_ms == 1000, "aggregate warning reported the wrong interval");
    require(report.total == 11, "aggregate warning reported the wrong lifetime total");
    require(stats.suppressed == 0, "aggregate report did not reset the suppressed count");
    require(stats.last_report_ms == 2000, "aggregate report did not advance the clock");
}

// Case 8: a later discard after the interval reports the suppressed count and the
// running lifetime total, using a fresh window after the previous report reset.
static void testReportAfterResetUsesNewWindow(void)
{
    tun_oversized_read_discard_stats_t stats = {0};

    require(! tunWindowsAccountOversizedReadDiscard(&stats, 1000).should_log, "arming discard logged");
    tun_oversized_read_discard_report_t first = tunWindowsAccountOversizedReadDiscard(&stats, 2000);
    require(first.should_log, "first window did not report");
    require(first.total == 2, "first window total mismatch");

    // A new drop starts a new window; nothing is logged until the interval passes.
    require(! tunWindowsAccountOversizedReadDiscard(&stats, 2100).should_log, "new-window discard logged early");

    tun_oversized_read_discard_report_t second = tunWindowsAccountOversizedReadDiscard(&stats, 3500);
    require(second.should_log, "second window did not report after the interval");
    require(second.discarded == 2, "second window miscounted its own discards");
    require(second.elapsed_ms == 1500, "second window reported the wrong interval");
    require(second.total == 4, "second window reported the wrong lifetime total");
}

// Case 9: pending suppressed drops are reported once during reader cleanup, and a
// follow-up flush with nothing pending stays silent.
static void testPendingFlushReportsRemainderOnce(void)
{
    tun_oversized_read_discard_stats_t stats = {0};

    require(! tunWindowsAccountOversizedReadDiscard(&stats, 5000).should_log, "arming discard logged");
    require(! tunWindowsAccountOversizedReadDiscard(&stats, 5200).should_log, "within-window discard logged");

    tun_oversized_read_discard_report_t flush = tunWindowsAccountPendingOversizedReadDiscards(&stats);
    require(flush.should_log, "pending flush did not report suppressed discards");
    require(flush.discarded == 2, "pending flush miscounted suppressed discards");
    require(flush.total == 2, "pending flush reported the wrong lifetime total");
    require(stats.suppressed == 0, "pending flush did not clear the suppressed count");

    require(! tunWindowsAccountPendingOversizedReadDiscards(&stats).should_log,
            "pending flush warned with nothing suppressed");
}

// A pending flush right after an aggregate report (suppressed already zero) is silent.
static void testPendingFlushSilentAfterAggregateReport(void)
{
    tun_oversized_read_discard_stats_t stats = {0};

    require(! tunWindowsAccountOversizedReadDiscard(&stats, 1000).should_log, "arming discard logged");
    require(tunWindowsAccountOversizedReadDiscard(&stats, 2000).should_log, "aggregate report was not emitted");
    require(! tunWindowsAccountPendingOversizedReadDiscards(&stats).should_log,
            "pending flush warned after the aggregate report already drained the window");
}

int main(void)
{
    testPacketSizeDecision();
    testFirstDiscardIsSilentButCounted();
    testRepeatedDiscardsAggregateIntoOneWindow();
    testReportAfterResetUsesNewWindow();
    testPendingFlushReportsRemainderOnce();
    testPendingFlushSilentAfterAggregateReport();
    return 0;
}
