#include "capture_windows_lifetime.h"

#include <stdio.h>
#include <stdlib.h>

typedef struct lifetime_probe_s
{
    unsigned int                  sequence;
    unsigned int                  begin_step;
    unsigned int                  shutdown_step;
    unsigned int                  join_step;
    unsigned int                  close_step;
    unsigned int                  begin_calls;
    unsigned int                  shutdown_calls;
    unsigned int                  join_calls;
    unsigned int                  close_calls;
    bool                          handle_live;
    bool                          reader_handle_live;
    bool                          reader_may_be_running;
    bool                          shutdown_succeeds;
    bool                          close_succeeds;
    capture_windows_join_result_e join_result;
} lifetime_probe_t;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static unsigned int nextStep(lifetime_probe_t *probe)
{
    probe->sequence++;
    return probe->sequence;
}

static void probeBeginShutdown(void *context)
{
    lifetime_probe_t *probe = context;
    probe->begin_calls++;
    probe->begin_step = nextStep(probe);
}

static bool probeHasHandle(const void *context)
{
    const lifetime_probe_t *probe = context;
    return probe->handle_live;
}

static bool probeReaderMayBeRunning(const void *context)
{
    const lifetime_probe_t *probe = context;
    return probe->reader_may_be_running;
}

static bool probeHasReader(const void *context)
{
    const lifetime_probe_t *probe = context;
    return probe->reader_handle_live;
}

static bool probeShutdownHandle(void *context)
{
    lifetime_probe_t *probe = context;
    probe->shutdown_calls++;
    probe->shutdown_step = nextStep(probe);
    return probe->shutdown_succeeds;
}

static capture_windows_join_result_e probeJoinReader(void *context)
{
    lifetime_probe_t *probe = context;
    probe->join_calls++;
    probe->join_step = nextStep(probe);
    if (probe->join_result != kCaptureWindowsJoinResultNotStopped)
    {
        probe->reader_may_be_running = false;
    }
    if (probe->join_result == kCaptureWindowsJoinResultStopped)
    {
        probe->reader_handle_live = false;
    }
    return probe->join_result;
}

static bool probeCloseHandle(void *context)
{
    lifetime_probe_t *probe = context;
    probe->close_calls++;
    probe->close_step = nextStep(probe);
    if (! probe->close_succeeds)
    {
        return false;
    }
    probe->handle_live = false;
    return true;
}

static const capture_windows_lifetime_ops_t probe_ops = {
    .begin_shutdown        = probeBeginShutdown,
    .has_handle            = probeHasHandle,
    .has_reader            = probeHasReader,
    .reader_may_be_running = probeReaderMayBeRunning,
    .shutdown_handle       = probeShutdownHandle,
    .join_reader           = probeJoinReader,
    .close_handle          = probeCloseHandle,
};

static lifetime_probe_t newProbe(void)
{
    return (lifetime_probe_t) {
        .handle_live           = true,
        .reader_handle_live    = true,
        .reader_may_be_running = true,
        .shutdown_succeeds     = true,
        .close_succeeds        = true,
        .join_result           = kCaptureWindowsJoinResultStopped,
    };
}

static void testSuccessfulShutdownOrdering(void)
{
    lifetime_probe_t probe = newProbe();

    require(captureWindowsLifetimeShutdown(&probe, &probe_ops), "normal shutdown failed");
    require(probe.begin_step < probe.shutdown_step, "shutdown occurred before stopping state was published");
    require(probe.shutdown_step < probe.join_step, "reader joined before WinDivert shutdown");
    require(probe.join_step < probe.close_step, "WinDivert handle closed before reader joined");
    require(! probe.handle_live, "successful shutdown retained the WinDivert handle");
}

static void testShutdownFailurePreservesLiveReaderResources(void)
{
    lifetime_probe_t probe  = newProbe();
    probe.shutdown_succeeds = false;

    require(! captureWindowsLifetimeShutdown(&probe, &probe_ops), "shutdown failure reported success");
    require(probe.join_calls == 0, "shutdown failure attempted an unbounded join");
    require(probe.close_calls == 0, "shutdown failure closed the handle under a live reader");
    require(probe.handle_live, "shutdown failure discarded the WinDivert handle");
}

static void testShutdownFailureAfterProvenExitCanStillClose(void)
{
    lifetime_probe_t probe      = newProbe();
    probe.shutdown_succeeds     = false;
    probe.reader_may_be_running = false;

    require(captureWindowsLifetimeShutdown(&probe, &probe_ops),
            "shutdown failure retained resources after reader exit was already proven");
    require(probe.join_calls == 1, "proven-exit cleanup skipped thread-handle release");
    require(probe.close_calls == 1, "proven-exit cleanup skipped WinDivert close");
}

static void testJoinFailurePreservesHandle(void)
{
    lifetime_probe_t probe = newProbe();
    probe.join_result      = kCaptureWindowsJoinResultNotStopped;

    require(! captureWindowsLifetimeShutdown(&probe, &probe_ops), "join failure reported success");
    require(probe.close_calls == 0, "join failure closed the WinDivert handle");
    require(probe.handle_live, "join failure discarded the WinDivert handle");
}

static void testThreadHandleReleaseFailureStillClosesWinDivert(void)
{
    lifetime_probe_t probe = newProbe();
    probe.join_result      = kCaptureWindowsJoinResultStoppedHandleReleaseFailed;

    require(! captureWindowsLifetimeShutdown(&probe, &probe_ops), "thread-handle release failure reported success");
    require(probe.close_calls == 1, "proven reader exit did not permit WinDivert close");
    require(! probe.handle_live, "WinDivert handle remained after the reader was proven stopped");
    require(probe.reader_handle_live, "failed thread-handle release discarded the retained handle");

    probe.join_result = kCaptureWindowsJoinResultStopped;
    require(captureWindowsLifetimeShutdown(&probe, &probe_ops), "thread-handle release retry failed");
    require(probe.close_calls == 1, "thread-handle release retry closed WinDivert twice");
    require(! probe.reader_handle_live, "thread-handle release retry retained the thread handle");
}

static void testCloseFailureRetainsHandleForRetry(void)
{
    lifetime_probe_t probe = newProbe();
    probe.close_succeeds   = false;

    require(! captureWindowsLifetimeShutdown(&probe, &probe_ops), "close failure reported success");
    require(probe.handle_live, "close failure cleared the WinDivert handle");

    probe.close_succeeds = true;
    require(captureWindowsLifetimeShutdown(&probe, &probe_ops), "close retry failed");
    require(probe.close_calls == 2, "close retry did not retry exactly once");
    require(! probe.handle_live, "close retry retained the WinDivert handle");
}

static void testReaderCreationFailureRollback(void)
{
    lifetime_probe_t probe      = newProbe();
    probe.reader_handle_live    = false;
    probe.reader_may_be_running = false;

    require(captureWindowsLifetimeRollbackOpen(&probe, &probe_ops), "reader creation rollback failed");
    require(probe.shutdown_calls == 0, "reader creation rollback unnecessarily shut down WinDivert");
    require(probe.join_calls == 0, "reader creation rollback attempted a join");
    require(probe.close_calls == 1, "reader creation rollback did not close WinDivert");

    lifetime_probe_t close_failure      = newProbe();
    close_failure.reader_handle_live    = false;
    close_failure.reader_may_be_running = false;
    close_failure.close_succeeds        = false;
    require(! captureWindowsLifetimeRollbackOpen(&close_failure, &probe_ops),
            "reader creation rollback close failure reported success");
    require(close_failure.handle_live, "reader creation rollback discarded a failed-close handle");

    lifetime_probe_t live_reader = newProbe();
    require(! captureWindowsLifetimeRollbackOpen(&live_reader, &probe_ops),
            "startup rollback closed a handle owned by a live reader");
    require(live_reader.close_calls == 0, "startup rollback closed WinDivert under a live reader");
}

static void testPartialStartupAndRepeatedShutdown(void)
{
    lifetime_probe_t partial      = newProbe();
    partial.reader_handle_live    = false;
    partial.reader_may_be_running = false;

    require(captureWindowsLifetimeShutdown(&partial, &probe_ops), "partial-startup shutdown failed");
    require(partial.shutdown_calls == 1, "partial-startup shutdown skipped WinDivert shutdown");
    require(partial.join_calls == 1, "partial-startup shutdown skipped the empty thread slot");
    require(partial.close_calls == 1, "partial-startup shutdown skipped WinDivert close");

    require(captureWindowsLifetimeShutdown(&partial, &probe_ops), "repeated shutdown failed");
    require(partial.shutdown_calls == 1, "repeated shutdown shut down WinDivert twice");
    require(partial.close_calls == 1, "repeated shutdown closed WinDivert twice");
}

int main(void)
{
    testSuccessfulShutdownOrdering();
    testShutdownFailurePreservesLiveReaderResources();
    testShutdownFailureAfterProvenExitCanStillClose();
    testJoinFailurePreservesHandle();
    testThreadHandleReleaseFailureStillClosesWinDivert();
    testCloseFailureRetainsHandleForRetry();
    testReaderCreationFailureRollback();
    testPartialStartupAndRepeatedShutdown();
    return 0;
}
