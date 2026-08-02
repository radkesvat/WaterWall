#include "wwapi.h"

#include "devices/capture/capture.h"
#include "devices/capture/capture_linux_internal.h"

#include "worker_messages.h"

#include "worker_registry_fixture.h"
#include <poll.h>
#include <unistd.h>

/*
 * Fake worker table for the stubbed GSTATE below. Without it the identity
 * predicates correctly report "not an event worker" and the checked
 * current-worker accessors reject this test.
 */
static test_worker_registry_t g_test_worker_registry;

enum
{
    kCaptureRangeCount = 2,
    kQueueNumber       = 77
};

static const char *const test_cidrs[kCaptureRangeCount] = {
    "10.0.0.0/8",
    "192.168.0.0/16",
};

typedef struct captured_message_s
{
    WorkerMessageCleanupCallback cleanup;
    void                        *arg1;
    void                        *arg2;
    void                        *arg3;
} captured_message_t;

typedef struct test_env_s
{
    master_pool_t *large_master;
    master_pool_t *small_master;
    buffer_pool_t *worker_buffer_pool;
    buffer_pool_t *buffer_pools[1];
    wloop_t       *loops[1];
} test_env_t;

static captured_message_t       captured_message;
static unsigned int             captured_message_count;
static unsigned int             command_index;
static capture_device_t        *posting_device;
static device_reader_session_t *tracked_session;
static master_pool_t           *tracked_message_pool;
static unsigned int             tracked_session_free_count;
static unsigned int             tracked_pool_destroy_count;

bool __wrap_procRunArgvWithDeadline(const char *file, const char *const argv[], const proc_command_options_t *options,
                                    proc_command_result_t *out);
void __real_procCommandResultDrop(proc_command_result_t *out);
void __wrap_procCommandResultDrop(proc_command_result_t *out);
bool __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                   WorkerMessageCleanupCallback cleanup, void *arg1, void *arg2,
                                                   void *arg3);
void __real_memoryFree(void *ptr);
void __wrap_memoryFree(void *ptr);
void __real_masterpoolDestroy(master_pool_t *pool);
void __wrap_masterpoolDestroy(master_pool_t *pool);

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

bool __wrap_procRunArgvWithDeadline(const char *file, const char *const argv[], const proc_command_options_t *options,
                                    proc_command_result_t *out)
{
    require(file != NULL && argv != NULL && options != NULL && out != NULL,
            "Capture submitted an incomplete process request");
    memoryZero(out, sizeof(*out));

    if (strcmp(file, "sysctl") == 0)
    {
        out->exit_code = 0;
        return true;
    }

    require(strcmp(file, "iptables") == 0, "Capture attempted to execute an unexpected program");
    require(command_index < 3, "Capture issued an unexpected firewall command");

    const char *operation = argv[3];
    const char *cidr      = argv[6];
    switch (command_index++)
    {
    case 0:
        require(strcmp(operation, "-I") == 0 && strcmp(cidr, test_cidrs[0]) == 0,
                "Capture did not install rule 0 first");
        out->exit_code = 0;
        return true;

    case 1: {
        require(strcmp(operation, "-I") == 0 && strcmp(cidr, test_cidrs[1]) == 0,
                "Capture did not attempt rule 1 after rule 0");
        require(posting_device != NULL, "the failing insertion has no capture device");

        sbuf_t *buf = bufferpoolGetLargeBuffer(posting_device->reader_buffer_pool);
        deviceReaderSessionPost(posting_device->reader_session, 0, &buf, 1);
        require(captured_message_count == 1, "the startup packet was not queued before insertion failed");

        out->exit_code = 1;
        return false;
    }

    case 2:
        require(strcmp(operation, "-D") == 0 && strcmp(cidr, test_cidrs[0]) == 0,
                "Capture did not roll back rule 0 after rule 1 failed");
        out->exit_code = 0;
        return true;

    default:
        require(false, "unreachable firewall command index");
        return false;
    }
}

void __wrap_procCommandResultDrop(proc_command_result_t *out)
{
    __real_procCommandResultDrop(out);
}

bool __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                   WorkerMessageCleanupCallback cleanup, void *arg1, void *arg2,
                                                   void *arg3)
{
    discard wid;
    discard callback;
    require(captured_message_count == 0, "Capture queued more than one test message");
    captured_message = (captured_message_t) {
        .cleanup = cleanup,
        .arg1    = arg1,
        .arg2    = arg2,
        .arg3    = arg3,
    };
    captured_message_count = 1;
    return true;
}

void __wrap_memoryFree(void *ptr)
{
    if (ptr == tracked_session)
    {
        tracked_session_free_count++;
    }
    __real_memoryFree(ptr);
}

void __wrap_masterpoolDestroy(master_pool_t *pool)
{
    if (pool == tracked_message_pool)
    {
        tracked_pool_destroy_count++;
    }
    __real_masterpoolDestroy(pool);
}

static WTHREAD_ROUTINE(testCaptureReader)
{
    capture_device_t *cdev          = userdata;
    int               reader_socket = -1;
    if (! captureLinuxReaderPublishReady(cdev, &reader_socket))
    {
        return NULL;
    }
    require(reader_socket >= 0, "Capture did not publish its queue socket to the reader");

    struct pollfd stop_fd = {
        .fd     = cdev->linux_pipe_fds[0],
        .events = POLLIN,
    };
    while (atomicLoadExplicit(&cdev->running, memory_order_acquire))
    {
        stop_fd.revents = 0;
        int result      = poll(&stop_fd, 1, 20);
        if (result > 0 && (stop_fd.revents & POLLIN) != 0)
        {
            char    token;
            ssize_t received = read(stop_fd.fd, &token, 1);
            discard received;
            break;
        }
    }
    return 0;
}

static void deliverPacket(void *device, sbuf_t *buf, wid_t wid)
{
    discard device;
    bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
}

static void envSetup(test_env_t *env)
{
    memoryZero(env, sizeof(*env));
    env->large_master       = masterpoolCreateWithCapacity(16);
    env->small_master       = masterpoolCreateWithCapacity(16);
    env->worker_buffer_pool = bufferpoolCreate(env->large_master, env->small_master, 16, 8192, 4096);
    env->buffer_pools[0]    = env->worker_buffer_pool;
    env->loops[0]           = (wloop_t *) (void *) env;

    GSTATE.shortcut_buffer_pools         = env->buffer_pools;
    GSTATE.shortcut_loops                = env->loops;
    GSTATE.masterpool_buffer_pools_large = env->large_master;
    GSTATE.masterpool_buffer_pools_small = env->small_master;
    GSTATE.workers_count                 = 1;
    testWorkerRegistryInstall(&g_test_worker_registry);
    GSTATE.ram_profile = 1;
    atomicStoreExplicit(&GSTATE.application_stopping_flag, false, memory_order_release);
    testWorkerBindWID(0);
}

static void envTeardown(test_env_t *env)
{
    GSTATE.shortcut_buffer_pools         = NULL;
    GSTATE.shortcut_loops                = NULL;
    GSTATE.masterpool_buffer_pools_large = NULL;
    GSTATE.masterpool_buffer_pools_small = NULL;
    GSTATE.workers_count                 = 0;
    testWorkerRegistryRestore(&g_test_worker_registry);

    bufferpoolDestroy(env->worker_buffer_pool);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->small_master);
}

static capture_device_t *createDevice(test_env_t *env)
{
    capture_device_t *cdev    = memoryAllocateZero(sizeof(*cdev));
    cdev->name                = stringDuplicate("capture-message-lifetime-test");
    cdev->socket              = dup(STDERR_FILENO);
    cdev->queue_number        = kQueueNumber;
    cdev->capture_range_count = kCaptureRangeCount;
    cdev->capture_cidrs       = memoryAllocateZero(kCaptureRangeCount * sizeof(char *));
    cdev->rule_states         = memoryAllocateZero(kCaptureRangeCount * sizeof(*cdev->rule_states));
    cdev->rule_token          = UINT64_C(0x1122334455667788);
    cdev->queue_restartable   = true;
    cdev->routine_reader      = testCaptureReader;
    cdev->reader_buffer_pool  = bufferpoolCreate(env->large_master, env->small_master, 16, 8192, 4096);
    atomic_init(&cdev->lifecycle, kCaptureLifecycleDown);
    require(cdev->socket >= 0, "failed to create the queue-socket stand-in");

    for (uint32_t i = 0; i < kCaptureRangeCount; i++)
    {
        cdev->capture_cidrs[i] = stringDuplicate(test_cidrs[i]);
    }

    require(pipe(cdev->linux_pipe_fds) == 0, "failed to create the capture stop pipe");
    require(capturedeviceMakeStopPipeNonblocking(cdev->linux_pipe_fds[0]),
            "failed to make the capture stop pipe nonblocking");
    require(pthread_mutex_init(&cdev->reader_state_mutex, NULL) == 0, "failed to initialize the capture reader mutex");
    require(pthread_cond_init(&cdev->reader_state_changed, NULL) == 0,
            "failed to initialize the capture reader condition variable");

    cdev->reader_session = deviceReaderSessionCreate(4, 512, cdev, deliverPacket, cdev->reader_buffer_pool);
    return cdev;
}

static void testQueuedCleanupOutlivesCaptureStartupFailure(test_env_t *env)
{
    capture_device_t *cdev = createDevice(env);
    posting_device         = cdev;
    tracked_session        = cdev->reader_session;
    tracked_message_pool   = tracked_session->message_pool;

    require(! caputredeviceBringUp(cdev), "partial rule installation unexpectedly succeeded");
    posting_device = NULL;
    require(command_index == 3, "Capture did not complete the expected installation rollback");
    require(! atomicLoadExplicit(&cdev->up, memory_order_acquire) &&
                ! atomicLoadExplicit(&cdev->running, memory_order_acquire) && ! cdev->reader_thread_joinable,
            "Capture left its reader running after installation rollback");
    require(atomicLoadExplicit(&tracked_session->refcount, memory_order_acquire) == 2,
            "the queued startup message did not retain its reader session");

    capturedeviceDestroy(cdev);
    require(atomicLoadExplicit(&tracked_session->refcount, memory_order_acquire) == 1,
            "Capture destruction did not release exactly its session reference");
    require(tracked_session_free_count == 0 && tracked_pool_destroy_count == 0,
            "Capture destruction freed a session retained by a queued message");

    captured_message.cleanup(captured_message.arg1, captured_message.arg2, captured_message.arg3);
    require(tracked_session_free_count == 1, "queued cleanup did not free the Capture session exactly once");
    require(tracked_pool_destroy_count == 1, "queued cleanup did not destroy the Capture message pool exactly once");
}

int main(void)
{
    test_env_t env;
    envSetup(&env);
    testQueuedCleanupOutlivesCaptureStartupFailure(&env);
    envTeardown(&env);
    puts("Linux Capture startup-message lifetime tests passed");
    return 0;
}
