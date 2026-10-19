/* Windows reader stop ordering: close admission, quiesce native notifications
 * and owner reads, settle delivery/writes, retire storage, then end Wintun.
 * CTest: waterwall.tun_windows_lifetime_unit */
#include "tun_windows_lifetime.h"

#include "test_assert.h"
#include "wwapi.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

typedef struct lifetime_probe_s
{
    unsigned int sequence;
    unsigned int begin_step;
    unsigned int reader_quiesce_step;
    unsigned int reader_wait_step;
    unsigned int writes_wait_step;
    unsigned int reader_retire_step;
    unsigned int session_end_step;
    unsigned int reader_retire_calls;
    unsigned int session_end_calls;
    bool         reader_retire_succeeds;
    bool         reader_callbacks_live;
    bool         reader_resources_live;
    bool         writes_in_flight;
    bool         session_live;
} lifetime_probe_t;

static void probeBeginShutdown(void *context)
{
    lifetime_probe_t *probe = context;
    probe->begin_step       = ++probe->sequence;
}

static void probeQuiesceReader(void *context)
{
    lifetime_probe_t *probe = context;
    require(probe->begin_step != 0, "quiesced notification before closing admission");
    probe->reader_quiesce_step   = ++probe->sequence;
    probe->reader_callbacks_live = false;
}

static void probeWaitReaderDelivery(void *context)
{
    lifetime_probe_t *probe = context;
    require(! probe->reader_callbacks_live, "delivery wait started before the reader settled");
    probe->reader_wait_step = ++probe->sequence;
}

static void probeWaitWrites(void *context)
{
    lifetime_probe_t *probe = context;
    probe->writes_wait_step = ++probe->sequence;
    probe->writes_in_flight = false;
}

static bool probeRetireReader(void *context)
{
    lifetime_probe_t *probe = context;
    require(! probe->reader_callbacks_live, "retired storage before native notification quiesced");
    probe->reader_retire_step = ++probe->sequence;
    if (! probe->reader_retire_succeeds)
        return false;
    if (probe->reader_resources_live)
    {
        probe->reader_retire_calls++;
        probe->reader_resources_live = false;
    }
    return true;
}

static void probeEndSession(void *context)
{
    lifetime_probe_t *probe = context;
    require(! probe->writes_in_flight && ! probe->reader_callbacks_live && ! probe->reader_resources_live,
            "session ended with reachable native resources");
    probe->session_end_step = ++probe->sequence;
    if (probe->session_live)
    {
        probe->session_end_calls++;
        probe->session_live = false;
    }
}

static const tun_windows_lifetime_ops_t probe_ops = {
    .begin_shutdown       = probeBeginShutdown,
    .quiesce_reader       = probeQuiesceReader,
    .wait_reader_delivery = probeWaitReaderDelivery,
    .wait_writes          = probeWaitWrites,
    .retire_reader        = probeRetireReader,
    .end_session          = probeEndSession,
};

static lifetime_probe_t newProbe(void)
{
    return (lifetime_probe_t) {
        .reader_retire_succeeds = true,
        .reader_callbacks_live  = true,
        .reader_resources_live  = true,
        .writes_in_flight       = true,
        .session_live           = true,
    };
}

static void testSuccessfulShutdownOrdering(void)
{
    lifetime_probe_t probe = newProbe();
    require(tunWindowsLifetimeShutdown(&probe, &probe_ops), "normal shutdown failed");
    require(probe.begin_step < probe.reader_quiesce_step, "reader quiesced before closing admission");
    require(probe.reader_quiesce_step < probe.reader_wait_step, "delivery waited before reader quiescence");
    require(probe.reader_wait_step < probe.reader_retire_step, "retired generation before delivery quiesced");
    require(probe.writes_wait_step < probe.session_end_step, "session ended before native writes quiesced");
    require(probe.reader_retire_step < probe.session_end_step, "session ended before reader retirement");
}

static void testReaderStartupFailure(void)
{
    lifetime_probe_t probe      = newProbe();
    probe.reader_callbacks_live = false;
    require(tunWindowsLifetimeShutdown(&probe, &probe_ops), "reader-startup rollback failed");
    require(probe.session_end_calls == 1 && probe.reader_retire_calls == 1,
            "reader-startup rollback retained session or storage");
}

static void testReaderRetireFailurePreservesSession(void)
{
    lifetime_probe_t probe       = newProbe();
    probe.reader_retire_succeeds = false;
    require(! tunWindowsLifetimeShutdown(&probe, &probe_ops), "reader retirement failure reported success");
    require(probe.session_end_calls == 0, "session ended after reader retirement failed");
    probe.reader_retire_succeeds = true;
    require(tunWindowsLifetimeShutdown(&probe, &probe_ops), "reader retirement retry failed");
    require(probe.reader_retire_calls == 1 && probe.session_end_calls == 1,
            "reader retirement retry did not release resources exactly once");
}

static void testRepeatedShutdownIsIdempotent(void)
{
    lifetime_probe_t probe = newProbe();
    require(tunWindowsLifetimeShutdown(&probe, &probe_ops), "initial shutdown failed");
    require(tunWindowsLifetimeShutdown(&probe, &probe_ops), "repeated shutdown failed");
    require(probe.reader_retire_calls == 1 && probe.session_end_calls == 1,
            "repeated shutdown released resources twice");
}

int main(void)
{
    testCaseSet("tun_windows_lifetime_test");
    testSuccessfulShutdownOrdering();
    testReaderStartupFailure();
    testReaderRetireFailurePreservesSession();
    testRepeatedShutdownIsIdempotent();
    return 0;
}
