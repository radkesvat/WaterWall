#include "wwapi.h"

#include <pthread.h>

static bool inject_pthread_create_failure;

int __real_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg);
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg);

int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg)
{
    if (inject_pthread_create_failure)
    {
        discard thread;
        discard attr;
        discard start_routine;
        discard arg;
        return EAGAIN;
    }

    return __real_pthread_create(thread, attr, start_routine, arg);
}

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static WTHREAD_ROUTINE(threadCreationSuccessRoutine)
{
    atomic_bool *ran = userdata;
    require(getWID() == kInvalidWID, "plain threadCreate thread did not observe kInvalidWID");
    require(! currentThreadHasRegisteredWID(), "plain threadCreate thread reported registered WID");
    atomic_store(ran, true);
    return 0;
}

static void testThreadCreateFailureLeavesOutputUntouched(void)
{
    wthread_t     thread;
    unsigned char before[sizeof(thread)];
    memset(&thread, 0xA5, sizeof(thread));
    memcpy(before, &thread, sizeof(before));

    inject_pthread_create_failure = true;
    wthread_error_t error         = threadCreate(&thread, threadCreationSuccessRoutine, NULL);
    inject_pthread_create_failure = false;

    require(error == EAGAIN, "threadCreate did not return the pthread_create error");
    require(memcmp(before, &thread, sizeof(before)) == 0, "threadCreate modified output after failure");
}

static void testThreadCreateSuccessStillJoins(void)
{
    atomic_bool ran;
    atomic_init(&ran, false);

    wthread_t       thread;
    wthread_error_t error = threadCreate(&thread, threadCreationSuccessRoutine, &ran);
    require(error == kWThreadErrorNone, "threadCreate success returned an error");
    require(threadJoin(thread) == 0, "threadCreate success thread did not join cleanly");
    require(atomic_load(&ran), "threadCreate success routine did not run");
}

static void testWorkerSpawnFailureLeavesThreadInvalid(void)
{
    worker_t dummy_workers[2] = {{.wid = 0}, {.wid = 1}};
    GSTATE.flag_initialized   = true;
    GSTATE.workers_count      = 2;
    GSTATE.workers            = dummy_workers;

    worker_t *worker = &dummy_workers[1];

    inject_pthread_create_failure = true;
    wthread_error_t error         = workerSpawn(worker);
    inject_pthread_create_failure = false;

    require(error == EAGAIN, "workerSpawn did not return the pthread_create error");
    require(! worker->thread_valid, "failed workerSpawn published a valid thread");

    GSTATE.flag_initialized = false;
    GSTATE.workers_count    = 0;
    GSTATE.workers          = NULL;
}

static void testWorkerJoinClearsValidThread(void)
{
    worker_t worker = {.wid = 1};
    mutexInit(&worker.control_mutex);
    condmutexInit(&worker.control_condition_mutex);
    condvarInit(&worker.control_condition);
    atomic_init(&worker.lifecycle, kWorkerLifecycleInitialized);

    atomic_bool ran;
    atomic_init(&ran, false);
    wthread_error_t error = threadCreate(&worker.thread, threadCreationSuccessRoutine, &ran);
    require(error == kWThreadErrorNone, "worker join fixture thread creation failed");
    worker.thread_valid = true;

    require(workerJoin(&worker), "workerJoin rejected a joinable thread");
    require(! worker.thread_valid, "workerJoin did not clear thread validity");
    require(atomic_load(&ran), "workerJoin returned before the joined routine completed");

    contvarDestroy(&worker.control_condition);
    condmutexDestroy(&worker.control_condition_mutex);
    mutexDestroy(&worker.control_mutex);
}

int main(void)
{
    testThreadCreateFailureLeavesOutputUntouched();
    testThreadCreateSuccessStillJoins();
    testWorkerSpawnFailureLeavesThreadInvalid();
    testWorkerJoinClearsValidThread();
    return 0;
}
