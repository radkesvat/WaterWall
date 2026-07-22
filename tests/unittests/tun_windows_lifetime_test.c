#include "tun_windows_lifetime.h"

#include <stdio.h>
#include <stdlib.h>

typedef struct lifetime_probe_s
{
    unsigned int sequence;
    unsigned int begin_step;
    unsigned int signal_step;
    unsigned int reader_join_step;
    unsigned int writer_join_step;
    unsigned int writer_release_step;
    unsigned int session_end_step;
    unsigned int reader_join_calls;
    unsigned int writer_join_calls;
    unsigned int writer_release_calls;
    unsigned int session_end_calls;
    bool         signal_succeeds;
    bool         reader_join_succeeds;
    bool         writer_join_succeeds;
    bool         reader_thread_live;
    bool         writer_thread_live;
    bool         writer_resources_live;
    bool         session_live;
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
    probe->begin_step       = nextStep(probe);
}

static bool probeSignalReader(void *context)
{
    lifetime_probe_t *probe = context;
    probe->signal_step      = nextStep(probe);
    return probe->signal_succeeds;
}

static bool probeJoinReader(void *context)
{
    lifetime_probe_t *probe = context;
    probe->reader_join_calls++;
    probe->reader_join_step = nextStep(probe);
    if (! probe->reader_thread_live)
    {
        return true;
    }
    if (! probe->reader_join_succeeds)
    {
        return false;
    }
    probe->reader_thread_live = false;
    return true;
}

static bool probeJoinWriter(void *context)
{
    lifetime_probe_t *probe = context;
    probe->writer_join_calls++;
    probe->writer_join_step = nextStep(probe);
    if (! probe->writer_thread_live)
    {
        return true;
    }
    if (! probe->writer_join_succeeds)
    {
        return false;
    }
    probe->writer_thread_live = false;
    return true;
}

static void probeReleaseWriter(void *context)
{
    lifetime_probe_t *probe    = context;
    probe->writer_release_step = nextStep(probe);
    if (probe->writer_resources_live)
    {
        probe->writer_release_calls++;
        probe->writer_resources_live = false;
    }
}

static void probeEndSession(void *context)
{
    lifetime_probe_t *probe = context;
    probe->session_end_step = nextStep(probe);
    if (probe->session_live)
    {
        probe->session_end_calls++;
        probe->session_live = false;
    }
}

static const tun_windows_lifetime_ops_t probe_ops = {
    .begin_shutdown = probeBeginShutdown,
    .signal_reader  = probeSignalReader,
    .join_reader    = probeJoinReader,
    .join_writer    = probeJoinWriter,
    .release_writer = probeReleaseWriter,
    .end_session    = probeEndSession,
};

static lifetime_probe_t newProbe(void)
{
    return (lifetime_probe_t) {
        .signal_succeeds       = true,
        .reader_join_succeeds  = true,
        .writer_join_succeeds  = true,
        .reader_thread_live    = true,
        .writer_thread_live    = true,
        .writer_resources_live = true,
        .session_live          = true,
    };
}

static void testSuccessfulShutdownOrdering(void)
{
    lifetime_probe_t probe = newProbe();

    require(tunWindowsLifetimeShutdown(&probe, &probe_ops), "normal shutdown failed");
    require(probe.begin_step < probe.signal_step, "reader was signaled before shutdown began");
    require(probe.signal_step < probe.reader_join_step, "reader was joined before it was signaled");
    require(probe.reader_join_step < probe.writer_join_step, "writer was joined before reader");
    require(probe.writer_join_step < probe.writer_release_step, "writer resources were released before joins");
    require(probe.writer_release_step < probe.session_end_step, "session ended before writer resources released");
}

static void testSignalFailureUsesJoinFallback(void)
{
    lifetime_probe_t probe = newProbe();
    probe.signal_succeeds  = false;

    require(tunWindowsLifetimeShutdown(&probe, &probe_ops), "signal failure prevented bounded-wait cleanup");
    require(probe.reader_join_calls == 1, "signal failure skipped reader join");
    require(probe.writer_join_calls == 1, "signal failure skipped writer join");
    require(probe.session_end_calls == 1, "signal failure retained a fully joined session");
}

static void testJoinFailurePreservesResources(void)
{
    lifetime_probe_t probe     = newProbe();
    probe.reader_join_succeeds = false;

    require(! tunWindowsLifetimeShutdown(&probe, &probe_ops), "reader join failure reported success");
    require(probe.writer_join_calls == 1, "reader join failure skipped writer join");
    require(probe.writer_release_calls == 0, "writer resources released after a failed join");
    require(probe.session_end_calls == 0, "session ended after a failed join");

    probe.reader_join_succeeds = true;
    require(tunWindowsLifetimeShutdown(&probe, &probe_ops), "shutdown retry failed");
    require(probe.writer_release_calls == 1, "shutdown retry did not release writer resources");
    require(probe.session_end_calls == 1, "shutdown retry did not end session");
}

static void testPartialThreadStartup(void)
{
    lifetime_probe_t reader_failure   = newProbe();
    reader_failure.reader_thread_live = false;
    reader_failure.writer_thread_live = false;

    require(tunWindowsLifetimeShutdown(&reader_failure, &probe_ops), "reader-startup rollback failed");
    require(reader_failure.session_end_step > reader_failure.reader_join_step &&
                reader_failure.session_end_step > reader_failure.writer_join_step,
            "reader-startup rollback ended session before checking thread slots");

    lifetime_probe_t writer_failure   = newProbe();
    writer_failure.writer_thread_live = false;

    require(tunWindowsLifetimeShutdown(&writer_failure, &probe_ops), "writer-startup rollback failed");
    require(writer_failure.reader_join_calls == 1 && writer_failure.writer_join_calls == 1,
            "writer-startup rollback did not inspect both thread slots");
    require(writer_failure.session_end_step > writer_failure.reader_join_step &&
                writer_failure.session_end_step > writer_failure.writer_join_step,
            "writer-startup rollback ended session before joins");
}

static void testRepeatedShutdownIsIdempotent(void)
{
    lifetime_probe_t probe = newProbe();

    require(tunWindowsLifetimeShutdown(&probe, &probe_ops), "initial shutdown failed");
    require(tunWindowsLifetimeShutdown(&probe, &probe_ops), "repeated shutdown failed");
    require(probe.writer_release_calls == 1, "repeated shutdown released writer resources twice");
    require(probe.session_end_calls == 1, "repeated shutdown ended the session twice");
}

int main(void)
{
    testSuccessfulShutdownOrdering();
    testSignalFailureUsesJoinFallback();
    testJoinFailurePreservesResources();
    testPartialThreadStartup();
    testRepeatedShutdownIsIdempotent();
    return 0;
}
