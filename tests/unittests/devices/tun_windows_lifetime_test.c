/*
 * Covers: tun windows lifetime; the explicit inputs, callbacks and expected results below define this
 * suite.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Cases: testSuccessfulShutdownOrdering, testSignalFailureUsesJoinFallback,
 * testJoinFailurePreservesResources, testReaderStartupFailure, testReaderRetireFailurePreservesSession,
 * testRepeatedShutdownIsIdempotent
 * Checks: Assertion labels include: normal shutdown failed; reader was signaled before shutdown began;
 * reader delivery was waited before signaling; reader was joined before delivery quiesced
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.tun_windows_lifetime_unit
 */
#include "tun_windows_lifetime.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)
#include "wwapi.h"

typedef struct lifetime_probe_s
{
    unsigned int sequence;
    unsigned int begin_step;
    unsigned int signal_step;
    unsigned int reader_wait_step;
    unsigned int writes_wait_step;
    unsigned int reader_join_step;
    unsigned int reader_retire_step;
    unsigned int session_end_step;
    unsigned int reader_join_calls;
    unsigned int reader_wait_calls;
    unsigned int writes_wait_calls;
    unsigned int reader_retire_calls;
    unsigned int session_end_calls;
    bool         signal_succeeds;
    bool         reader_join_succeeds;
    bool         reader_retire_succeeds;
    bool         reader_thread_live;
    bool         reader_resources_live;
    bool         writes_in_flight;
    bool         session_live;
} lifetime_probe_t;


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

static void probeWaitReaderDelivery(void *context)
{
    lifetime_probe_t *probe = context;
    probe->reader_wait_calls++;
    probe->reader_wait_step = nextStep(probe);
}

static bool probeRetireReader(void *context)
{
    lifetime_probe_t *probe   = context;
    probe->reader_retire_step = nextStep(probe);
    if (! probe->reader_retire_succeeds)
    {
        return false;
    }
    if (probe->reader_resources_live)
    {
        probe->reader_retire_calls++;
        probe->reader_resources_live = false;
    }
    return true;
}

static void probeWaitWrites(void *context)
{
    lifetime_probe_t *probe = context;
    probe->writes_wait_calls++;
    probe->writes_wait_step = nextStep(probe);
    probe->writes_in_flight = false;
}

static void probeEndSession(void *context)
{
    lifetime_probe_t *probe = context;
    require(! probe->writes_in_flight, "session ended while native writes were active");
    require(! probe->reader_thread_live, "session ended while reader thread was active");
    probe->session_end_step = nextStep(probe);
    if (probe->session_live)
    {
        probe->session_end_calls++;
        probe->session_live = false;
    }
}

static const tun_windows_lifetime_ops_t probe_ops = {
    .begin_shutdown       = probeBeginShutdown,
    .signal_reader        = probeSignalReader,
    .wait_reader_delivery = probeWaitReaderDelivery,
    .wait_writes          = probeWaitWrites,
    .join_reader          = probeJoinReader,
    .retire_reader        = probeRetireReader,
    .end_session          = probeEndSession,
};

static lifetime_probe_t newProbe(void)
{
    return (lifetime_probe_t) {
        .signal_succeeds        = true,
        .reader_join_succeeds   = true,
        .reader_retire_succeeds = true,
        .reader_thread_live     = true,
        .reader_resources_live  = true,
        .writes_in_flight       = true,
        .session_live           = true,
    };
}

static void testSuccessfulShutdownOrdering(void)
{
    lifetime_probe_t probe = newProbe();

    require(tunWindowsLifetimeShutdown(&probe, &probe_ops), "normal shutdown failed");
    require(probe.begin_step < probe.signal_step, "reader was signaled before shutdown began");
    require(probe.signal_step < probe.reader_wait_step, "reader delivery was waited before signaling");
    require(probe.reader_wait_step < probe.reader_join_step, "reader was joined before delivery quiesced");
    require(probe.begin_step < probe.writes_wait_step, "writes were waited before admission closed");
    require(probe.reader_join_step < probe.reader_retire_step, "reader generation was retired before join");
    require(probe.writes_wait_step < probe.session_end_step, "session ended before native writes quiesced");
    require(probe.reader_retire_step < probe.session_end_step, "session ended before reader retirement");
}

static void testSignalFailureUsesJoinFallback(void)
{
    lifetime_probe_t probe = newProbe();
    probe.signal_succeeds  = false;

    require(tunWindowsLifetimeShutdown(&probe, &probe_ops), "signal failure prevented bounded-wait cleanup");
    require(probe.reader_join_calls == 1, "signal failure skipped reader join");
    require(probe.reader_wait_calls == 1, "signal failure skipped reader delivery wait");
    require(probe.writes_wait_calls == 1, "signal failure skipped native write wait");
    require(probe.session_end_calls == 1, "signal failure retained a fully joined session");
}

static void testJoinFailurePreservesResources(void)
{
    lifetime_probe_t probe     = newProbe();
    probe.reader_join_succeeds = false;

    require(! tunWindowsLifetimeShutdown(&probe, &probe_ops), "reader join failure reported success");
    require(probe.writes_wait_calls == 1, "reader join failure skipped native write wait");
    require(probe.reader_retire_calls == 0, "reader generation retired after a failed join");
    require(probe.session_end_calls == 0, "session ended after a failed join");

    probe.reader_join_succeeds = true;
    require(tunWindowsLifetimeShutdown(&probe, &probe_ops), "shutdown retry failed");
    require(! probe.writes_in_flight, "shutdown retry did not quiesce native writes");
    require(probe.session_end_calls == 1, "shutdown retry did not end session");
}

static void testReaderStartupFailure(void)
{
    lifetime_probe_t reader_failure   = newProbe();
    reader_failure.reader_thread_live = false;

    require(tunWindowsLifetimeShutdown(&reader_failure, &probe_ops), "reader-startup rollback failed");
    require(reader_failure.session_end_step > reader_failure.reader_join_step &&
                reader_failure.session_end_step > reader_failure.writes_wait_step,
            "reader-startup rollback ended session before I/O quiesced");
}

static void testReaderRetireFailurePreservesSession(void)
{
    lifetime_probe_t probe        = newProbe();
    probe.reader_retire_succeeds  = false;

    require(! tunWindowsLifetimeShutdown(&probe, &probe_ops), "reader retirement failure reported success");
    require(probe.session_end_calls == 0, "session ended after reader retirement failed");

    probe.reader_retire_succeeds = true;
    require(tunWindowsLifetimeShutdown(&probe, &probe_ops), "reader retirement retry failed");
    require(probe.reader_retire_calls == 1, "reader retirement retry did not release resources");
    require(probe.session_end_calls == 1, "reader retirement retry did not end session");
}

static void testRepeatedShutdownIsIdempotent(void)
{
    lifetime_probe_t probe = newProbe();

    require(tunWindowsLifetimeShutdown(&probe, &probe_ops), "initial shutdown failed");
    require(tunWindowsLifetimeShutdown(&probe, &probe_ops), "repeated shutdown failed");
    require(! probe.writes_in_flight, "repeated shutdown left native writes active");
    require(probe.reader_retire_calls == 1, "repeated shutdown retired reader resources twice");
    require(probe.session_end_calls == 1, "repeated shutdown ended the session twice");
}

int main(void)
{
    testCaseSet("tun_windows_lifetime_test");
    testSuccessfulShutdownOrdering();
    testSignalFailureUsesJoinFallback();
    testJoinFailurePreservesResources();
    testReaderStartupFailure();
    testReaderRetireFailurePreservesSession();
    testRepeatedShutdownIsIdempotent();
    return 0;
}
