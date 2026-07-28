#include "device_reader_session.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#if ! defined(NDEBUG) && ! defined(OS_WIN)
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

typedef struct gate_thread_probe_s
{
    device_lifetime_gate_t *gate;
    atomic_bool             started;
    atomic_bool             completed;
} gate_thread_probe_t;

typedef struct publication_probe_s
{
    device_lifetime_gate_t *gate;
    int                    *published_value;
    int                     observed_value;
} publication_probe_t;

typedef struct protected_write_probe_s
{
    device_lifetime_gate_t *gate;
    atomic_bool             entered;
    int                    *protected_value;
} protected_write_probe_t;

typedef struct pre_cas_probe_s
{
    device_lifetime_gate_t *gate;
    atomic_bool             selected;
    atomic_bool             resume;
    bool                    entered;
    int                    *published_value;
    int                     observed_value;
} pre_cas_probe_t;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void testDeliver(void *device, sbuf_t *buf, wid_t wid)
{
    discard device;
    discard buf;
    discard wid;
}

static device_reader_session_t *createTestSession(void)
{
    static int test_device;
    return deviceReaderSessionCreate(4, 1, &test_device, testDeliver, (buffer_pool_t *) (void *) &test_device);
}

static void *closeGateRoutine(void *userdata)
{
    gate_thread_probe_t *probe = userdata;
    atomicStoreRelaxed(&probe->started, true);
    deviceLifetimeGateCloseAndQuiesce(probe->gate, deviceLifetimeYieldThread, NULL);
    atomicStoreRelaxed(&probe->completed, true);
    return NULL;
}

static void *observePublicationRoutine(void *userdata)
{
    publication_probe_t *probe = userdata;
    while (! deviceLifetimeGateEnter(probe->gate))
    {
        YIELD_THREAD();
    }
    probe->observed_value = *probe->published_value;
    deviceLifetimeGateLeave(probe->gate);
    return NULL;
}

static void *writeProtectedValueRoutine(void *userdata)
{
    protected_write_probe_t *probe = userdata;
    require(deviceLifetimeGateEnter(probe->gate), "protected writer could not enter open gate");
    atomicStoreRelaxed(&probe->entered, true);
    *probe->protected_value = 73;
    deviceLifetimeGateLeave(probe->gate);
    return NULL;
}

static void pauseBeforeEnterCas(device_lifetime_gate_t *gate, void *context)
{
    pre_cas_probe_t *probe = context;
    require(gate == probe->gate, "pre-CAS hook received the wrong gate");
    atomicStoreRelaxed(&probe->selected, true);
    while (! atomicLoadRelaxed(&probe->resume))
    {
        YIELD_THREAD();
    }
}

static void *preCasEnterRoutine(void *userdata)
{
    pre_cas_probe_t *probe = userdata;
    probe->entered         = deviceLifetimeGateEnter(probe->gate);
    if (probe->entered)
    {
        probe->observed_value = *probe->published_value;
        deviceLifetimeGateLeave(probe->gate);
    }
    return NULL;
}

#if ! defined(NDEBUG) && ! defined(OS_WIN)
static void requireChildAborted(pid_t child, const char *message)
{
    int status;
    require(waitpid(child, &status, 0) == child, "failed to wait for debug contract child");
    require(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT, message);
}
#endif

static void testGateOpenEnterAndClose(void)
{
    device_lifetime_gate_t gate;
    deviceLifetimeGateInit(&gate);

    require(! deviceLifetimeGateIsActive(&gate), "a new gate was active");
    require(! deviceLifetimeGateEnter(&gate), "enter succeeded on a closed gate");

    require(deviceLifetimeGateOpen(&gate), "opening a closed gate failed");
    require(deviceLifetimeGateIsActive(&gate), "opening the gate did not publish it");
#ifdef NDEBUG
    require(! deviceLifetimeGateOpen(&gate), "double-open succeeded");
#elif ! defined(OS_WIN)
    const pid_t double_open_child = fork();
    require(double_open_child >= 0, "failed to fork double-open contract test");
    if (double_open_child == 0)
    {
        discard deviceLifetimeGateOpen(&gate);
        _Exit(0);
    }
    requireChildAborted(double_open_child, "debug double-open did not abort");
#endif
    require(deviceLifetimeGateEnter(&gate), "enter failed on an open gate");
    deviceLifetimeGateLeave(&gate);

    deviceLifetimeGateCloseAndQuiesce(&gate, deviceLifetimeYieldThread, NULL);
    deviceLifetimeGateCloseAndQuiesce(&gate, deviceLifetimeYieldThread, NULL);
    require(! deviceLifetimeGateEnter(&gate), "enter succeeded after close");
}

static void testCloseWaitsForLastLeave(void)
{
    device_lifetime_gate_t gate;
    deviceLifetimeGateInit(&gate);
    require(deviceLifetimeGateOpen(&gate), "failed to open close-wait gate");
    require(deviceLifetimeGateEnter(&gate), "failed to establish in-flight entrant");

    gate_thread_probe_t probe = {
        .gate      = &gate,
        .started   = false,
        .completed = false,
    };
    pthread_t closer;
    require(pthread_create(&closer, NULL, closeGateRoutine, &probe) == 0, "failed to create close thread");
    while (! atomicLoadRelaxed(&probe.started))
    {
        YIELD_THREAD();
    }
    for (unsigned int i = 0; i < 1000; i++)
    {
        require(! atomicLoadRelaxed(&probe.completed), "close returned while an entrant remained");
        YIELD_THREAD();
    }

    deviceLifetimeGateLeave(&gate);
    require(pthread_join(closer, NULL) == 0, "failed to join close thread");
    require(atomicLoadRelaxed(&probe.completed), "close did not complete after the final leave");
}

static void testCloseWinsBeforeEnterCas(void)
{
    device_lifetime_gate_t gate;
    deviceLifetimeGateInit(&gate);
    require(deviceLifetimeGateOpen(&gate), "failed to open close-before-CAS gate");

    int             published = 1;
    pre_cas_probe_t probe     = {
            .gate            = &gate,
            .selected        = false,
            .resume          = false,
            .entered         = false,
            .published_value = &published,
    };
    deviceLifetimeInstallBeforeEnterCasHook(pauseBeforeEnterCas, &probe);

    pthread_t entrant;
    require(pthread_create(&entrant, NULL, preCasEnterRoutine, &probe) == 0, "failed to create delayed gate entrant");
    while (! atomicLoadRelaxed(&probe.selected))
    {
        YIELD_THREAD();
    }

    deviceLifetimeGateCloseAndQuiesce(&gate, deviceLifetimeYieldThread, NULL);
    atomicStoreRelaxed(&probe.resume, true);
    require(pthread_join(entrant, NULL) == 0, "failed to join rejected delayed entrant");
    deviceLifetimeInstallBeforeEnterCasHook(NULL, NULL);
    require(! probe.entered, "an entrant whose CAS lost to close was admitted");
}

static void testDelayedEnterAcrossReopenObservesNewPublication(void)
{
    device_lifetime_gate_t gate;
    deviceLifetimeGateInit(&gate);

    int published = 11;
    require(deviceLifetimeGateOpen(&gate), "failed to open old publication");
    pre_cas_probe_t probe = {
        .gate            = &gate,
        .selected        = false,
        .resume          = false,
        .entered         = false,
        .published_value = &published,
        .observed_value  = 0,
    };
    deviceLifetimeInstallBeforeEnterCasHook(pauseBeforeEnterCas, &probe);

    pthread_t entrant;
    require(pthread_create(&entrant, NULL, preCasEnterRoutine, &probe) == 0, "failed to create delayed reopen entrant");
    while (! atomicLoadRelaxed(&probe.selected))
    {
        YIELD_THREAD();
    }

    deviceLifetimeGateCloseAndQuiesce(&gate, deviceLifetimeYieldThread, NULL);
    published = 29;
    require(deviceLifetimeGateOpen(&gate), "failed to publish reopened resource");
    atomicStoreRelaxed(&probe.resume, true);
    require(pthread_join(entrant, NULL) == 0, "failed to join delayed reopen entrant");
    deviceLifetimeInstallBeforeEnterCasHook(NULL, NULL);

    require(probe.entered, "delayed entrant did not select the reopened gate");
    require(probe.observed_value == published, "delayed entrant observed the old protected publication");
    deviceLifetimeGateCloseAndQuiesce(&gate, deviceLifetimeYieldThread, NULL);
}

static void testOpenPublishesAndCloseReclaimsProtectedWork(void)
{
    device_lifetime_gate_t gate;
    deviceLifetimeGateInit(&gate);

    int                 published         = 41;
    publication_probe_t publication_probe = {
        .gate            = &gate,
        .published_value = &published,
        .observed_value  = 0,
    };
    pthread_t observer;
    require(pthread_create(&observer, NULL, observePublicationRoutine, &publication_probe) == 0,
            "failed to create publication observer");
    require(deviceLifetimeGateOpen(&gate), "failed to publish gate-protected fields");
    require(pthread_join(observer, NULL) == 0, "failed to join publication observer");
    require(publication_probe.observed_value == published, "enter did not observe fields published before open");
    deviceLifetimeGateCloseAndQuiesce(&gate, deviceLifetimeYieldThread, NULL);

    require(deviceLifetimeGateOpen(&gate), "failed to reopen protected-write gate");
    int                     protected_value = 0;
    protected_write_probe_t write_probe     = {
            .gate            = &gate,
            .entered         = false,
            .protected_value = &protected_value,
    };
    pthread_t writer;
    require(pthread_create(&writer, NULL, writeProtectedValueRoutine, &write_probe) == 0,
            "failed to create protected writer");
    while (! atomicLoadRelaxed(&write_probe.entered))
    {
        YIELD_THREAD();
    }
    deviceLifetimeGateCloseAndQuiesce(&gate, deviceLifetimeYieldThread, NULL);
    require(pthread_join(writer, NULL) == 0, "failed to join protected writer");
    require(protected_value == 73, "close did not observe work completed before the final leave");
}

static void testSaturationFailsClosed(void)
{
    device_lifetime_gate_t gate;
    deviceLifetimeGateInit(&gate);
    atomicStoreRelaxed(&gate.state, DEVICE_LIFETIME_GATE_COUNT_MASK);

#ifdef NDEBUG
    require(! deviceLifetimeGateEnter(&gate), "saturated gate admitted another entrant");
    require(atomicLoadRelaxed(&gate.state) == DEVICE_LIFETIME_GATE_COUNT_MASK,
            "saturated enter corrupted packed state");
#elif ! defined(OS_WIN)
    const pid_t saturation_child = fork();
    require(saturation_child >= 0, "failed to fork saturation contract test");
    if (saturation_child == 0)
    {
        discard deviceLifetimeGateEnter(&gate);
        _Exit(0);
    }
    requireChildAborted(saturation_child, "debug saturation did not abort");
#endif

    atomicStoreRelaxed(&gate.state, DEVICE_LIFETIME_GATE_CLOSED);
}

#if ! defined(NDEBUG) && ! defined(OS_WIN)
static void testSameGateSelfCloseIsDebugContractFailure(void)
{
    device_lifetime_gate_t gate;
    deviceLifetimeGateInit(&gate);
    require(deviceLifetimeGateOpen(&gate), "failed to open self-close contract gate");

    const pid_t child = fork();
    require(child >= 0, "failed to fork self-close contract test");
    if (child == 0)
    {
        require(deviceLifetimeGateEnter(&gate), "debug self-close child could not enter");
        deviceLifetimeGateCloseAndQuiesce(&gate, deviceLifetimeYieldThread, NULL);
        _Exit(0);
    }
    requireChildAborted(child, "same-gate self-close did not abort in debug mode");
    deviceLifetimeGateCloseAndQuiesce(&gate, deviceLifetimeYieldThread, NULL);
}
#endif

static void testRepeatedCloseOpenCycles(void)
{
    device_lifetime_gate_t gate;
    deviceLifetimeGateInit(&gate);

    for (unsigned int i = 0; i < 1000; i++)
    {
        require(deviceLifetimeGateOpen(&gate), "repeated gate open failed");
        require(deviceLifetimeGateEnter(&gate), "repeated gate enter failed");
        deviceLifetimeGateLeave(&gate);
        deviceLifetimeGateCloseAndQuiesce(&gate, deviceLifetimeYieldThread, NULL);
    }
}

static void testSessionGenerationRejectsStaleAndWrap(void)
{
    device_reader_session_t *session = createTestSession();

    const uint32_t first_generation = deviceReaderSessionBegin(session);
    require(first_generation != 0, "first reader generation was invalid");
    require(deviceReaderSessionMatchesGeneration(session, first_generation),
            "the current generation did not match its stamp");

    deviceReaderSessionEnd(session);
    const uint32_t second_generation = deviceReaderSessionBegin(session);
    require(second_generation != 0 && second_generation != first_generation,
            "beginning a new session did not advance the generation");
    require(! deviceReaderSessionMatchesGeneration(session, first_generation),
            "a stale message stamp matched the new session");

    deviceReaderSessionEnd(session);
    atomicStoreRelaxed(&session->generation, UINT32_MAX);
    require(deviceReaderSessionBegin(session) == 0, "generation exhaustion reopened the reader gate");
    require(! deviceLifetimeGateIsActive(&session->delivery_gate), "generation exhaustion left delivery active");
    deviceReaderSessionUnref(session);
}

int main(void)
{
    testGateOpenEnterAndClose();
    testCloseWaitsForLastLeave();
    testCloseWinsBeforeEnterCas();
    testDelayedEnterAcrossReopenObservesNewPublication();
    testOpenPublishesAndCloseReclaimsProtectedWork();
    testSaturationFailsClosed();
#if ! defined(NDEBUG) && ! defined(OS_WIN)
    testSameGateSelfCloseIsDebugContractFailure();
#endif
    testRepeatedCloseOpenCycles();
    testSessionGenerationRejectsStaleAndWrap();
    puts("device lifetime tests passed");
    return 0;
}
