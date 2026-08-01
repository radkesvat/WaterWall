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
    worker_t worker = {.wid = 1};

    inject_pthread_create_failure = true;
    wthread_error_t error         = workerSpawn(&worker);
    inject_pthread_create_failure = false;

    require(error == EAGAIN, "workerSpawn did not return the pthread_create error");
    require(! worker.thread_valid, "failed workerSpawn published a valid thread");
}

static void testWorkerJoinClearsValidThread(void)
{
    worker_t worker = {.wid = 1};

    GSTATE = (ww_global_state_t) {0};
    atomic_init(&GSTATE.application_stopping_flag, true);
    atomic_init(&GSTATE.workers_run_flag, false);

    wthread_error_t error = workerSpawn(&worker);
    require(error == kWThreadErrorNone, "workerSpawn success returned an error");
    require(worker.thread_valid, "workerSpawn success did not publish a valid thread");

    workerJoin(&worker);
    require(! worker.thread_valid, "workerJoin did not clear thread validity");

    atomic_store(&GSTATE.application_stopping_flag, false);
}

int main(void)
{
    testThreadCreateFailureLeavesOutputUntouched();
    testThreadCreateSuccessStillJoins();
    testWorkerSpawnFailureLeavesThreadInvalid();
    testWorkerJoinClearsValidThread();
    return 0;
}
