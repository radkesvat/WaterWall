#include "threadsafe_generic_pool.h"
#include "wio_fd_pool_fixture.h"
#include "worker_registry_fixture.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct test_env_s
{
    test_worker_registry_t     registry;
    test_wio_fd_pool_t         descriptors;
    master_pool_t             *masters[4];
    buffer_pool_t             *buffers;
    threadsafe_generic_pool_t *wios;
    threadsafe_generic_pool_t *wio_pools[1];
    wloop_t                   *loop;
} test_env_t;

#if WW_HAVE_SPLICE
static bool fail_pipe;
int         __real_pipe2(int pipefd[2], int flags);
int         __wrap_pipe2(int pipefd[2], int flags);

int __wrap_pipe2(int pipefd[2], int flags)
{
    if (fail_pipe)
    {
        fail_pipe = false;
        errno     = EMFILE;
        return -1;
    }
    return __real_pipe2(pipefd, flags);
}
#endif

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void requireClosed(int fd)
{
    errno = 0;
    require(fcntl(fd, F_GETFD) == -1 && errno == EBADF, "descriptor survived the final release");
}

static void setup(test_env_t *env)
{
    memoryZero(env, sizeof(*env));
    GSTATE.workers_count = 2;
    testWorkerRegistryInstall(&env->registry);
    testWorkerBindWID(0);
    testWioFdPoolSetup(&env->descriptors);
    env->registry.slots[0].wio_fd_pool = env->descriptors.pool;
    for (size_t i = 0; i < ARRAY_SIZE(env->masters); ++i)
    {
        env->masters[i] = masterpoolCreateWithCapacity(8);
        require(env->masters[i] != NULL, "failed to create test master pool");
    }
    env->buffers = bufferpoolCreate(env->masters[0], env->masters[1], env->masters[2], 4, 4096, 1024);
    env->wios    = threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(env->masters[3], sizeof(wio_t), 4);
    require(env->buffers != NULL && env->wios != NULL, "failed to create test pools");
    env->wio_pools[0]          = env->wios;
    GSTATE.shortcut_wios_pools = env->wio_pools;
    env->loop                  = wloopCreate(WLOOP_FLAG_RUN_ONCE, env->buffers, 0);
    require(env->loop != NULL, "failed to create test loop");
}

static void teardown(test_env_t *env)
{
    wloopDestroy(&env->loop);
    require(masterpoolGetCheckedOut(env->descriptors.master) == 0, "descriptor pool retained a live object");
    env->registry.slots[0].wio_fd_pool = NULL;
    testWioFdPoolTeardown(&env->descriptors);
    GSTATE.shortcut_wios_pools = NULL;
    threadsafegenericpoolDestroy(env->wios);
    bufferpoolDestroy(env->buffers);
    for (size_t i = 0; i < ARRAY_SIZE(env->masters); ++i)
    {
        masterpoolMakeEmpty(env->masters[i]);
        masterpoolDestroy(env->masters[i]);
    }
    testWorkerUnbindWID();
    testWorkerRegistryRestore(&env->registry);
}

static wio_t *socketIO(test_env_t *env, int sockets[2])
{
    require(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0, "failed to create socket pair");
    wio_t *io = wioGet(env->loop, sockets[0]);
    require(io != NULL && wioIsOpened(io), "failed to wrap descriptor");
    wio_fd_t *handle = wioGetFDHandle(io);
    require(handle != NULL && handle->fd == sockets[0] && wiofdGetRefCount(handle) == 1,
            "new WIO did not adopt its descriptor with one reference");
    require(handle->pipefd[0] == 0 && handle->pipefd[1] == 0, "new/recycled descriptor object retained a pipe");
    return io;
}

static void testRetainedDescriptors(test_env_t *env)
{
    int       sockets[2];
    wio_t    *io     = socketIO(env, sockets);
    wio_fd_t *handle = wioGetFDHandle(io);
#if WW_HAVE_SPLICE
    fail_pipe = true;
    require(wioInitPipe(io) == -1 && errno == EMFILE, "pipe failure did not propagate");
    require(handle->pipefd[0] == 0 && handle->pipefd[1] == 0, "failed pipe initialization changed the object");
    require(wioInitPipe(io) == 0, "pipe creation failed");
    const int reader = handle->pipefd[0];
    const int writer = handle->pipefd[1];
    require(wioInitPipe(io) == 0 && handle->pipefd[0] == reader && handle->pipefd[1] == writer,
            "repeated pipe initialization replaced live descriptors");
    require((fcntl(reader, F_GETFL) & O_NONBLOCK) && (fcntl(writer, F_GETFL) & O_NONBLOCK), "splice pipe is blocking");
    require((fcntl(reader, F_GETFD) & FD_CLOEXEC) && (fcntl(writer, F_GETFD) & FD_CLOEXEC),
            "splice pipe is inheritable across exec");
#else
    require(wioInitPipe(io) == -1 && errno == ENOSYS, "unsupported pipe initialization did not fail");
    require(handle->pipefd[0] == 0 && handle->pipefd[1] == 0, "unsupported initialization changed pipe slots");
#endif
    wiofdRef(handle);
    require(wioClose(io) == 0 && wioGetFDHandle(io) == NULL && wioGetFD(io) == -1,
            "WIO close retained its descriptor reference");
    require(wioAdd(io, NULL, WW_READ) == -1, "closed WIO accepted new watcher interest");
    require(wiofdGetRefCount(handle) == 1 && fcntl(sockets[0], F_GETFD) >= 0,
            "WIO close closed an externally retained descriptor");
    char byte = 'x';
#if WW_HAVE_SPLICE
    require(write(writer, &byte, 1) == 1 && read(reader, &byte, 1) == 1, "retained pipe stopped working");
#endif
    require(send(handle->fd, &byte, 1, 0) == 1 && recv(sockets[1], &byte, 1, 0) == 1,
            "retained socket stopped working");
    wiofdUnref(handle);
    requireClosed(sockets[0]);
#if WW_HAVE_SPLICE
    requireClosed(reader);
    requireClosed(writer);
#endif

    require(dup2(sockets[1], sockets[0]) == sockets[0], "failed to reuse descriptor number");
    require(wioClose(io) == 0 && fcntl(sockets[0], F_GETFD) >= 0, "repeated close affected a reused descriptor");
    wio_t *reused = wioGet(env->loop, sockets[0]);
    require(reused == io && wiofdGetRefCount(wioGetFDHandle(reused)) == 1, "closed WIO was not reusable");
    require(reused->fd_handle->pipefd[0] == 0 && reused->fd_handle->pipefd[1] == 0,
            "WIO reuse retained pipe descriptors");
    wioClose(reused);
    close(sockets[1]);
}

static void testNoClose(test_env_t *env)
{
    int       sockets[2];
    wio_t    *io     = socketIO(env, sockets);
    wio_fd_t *handle = wioGetFDHandle(io);
#if WW_HAVE_SPLICE
    require(wioInitPipe(io) == 0, "failed to create no-close pipe");
    int reader = handle->pipefd[0], writer = handle->pipefd[1];
#endif
    wiofdRef(handle);
    wioReleaseNoClose(io);
    require(handle->fd == -1 && wiofdGetRefCount(handle) == 1,
            "watcher release did not relinquish descriptor ownership");
    require(fcntl(sockets[0], F_GETFD) >= 0, "watcher release closed the external descriptor");
    wiofdUnref(handle);
#if WW_HAVE_SPLICE
    requireClosed(reader);
    requireClosed(writer);
#endif
    require(fcntl(sockets[0], F_GETFD) >= 0, "final box release closed a relinquished descriptor");
    close(sockets[0]);
    close(sockets[1]);
}

static WTHREAD_ROUTINE(releaseHandle)
{
    require(tryGetCurrentEventWorker() == NULL, "foreign releaser inherited an event worker");
    wiofdUnref(userdata);
    return 0;
}

typedef struct foreign_create_s
{
    int       fd;
    wio_fd_t *handle;
} foreign_create_t;

static WTHREAD_ROUTINE(createHandle)
{
    foreign_create_t *create = userdata;
    create->handle           = wiofdCreate(create->fd);
    return 0;
}

static void testForeignReferences(test_env_t *env)
{
    for (unsigned int iteration = 0; iteration < 16; ++iteration)
    {
        int       sockets[2];
        wio_t    *io     = socketIO(env, sockets);
        wio_fd_t *handle = wioGetFDHandle(io);
        wiofdRef(handle);
        wiofdRef(handle);
        wioClose(io);
        wthread_t threads[2];
        require(threadCreate(&threads[0], releaseHandle, handle) == kWThreadErrorNone &&
                    threadCreate(&threads[1], releaseHandle, handle) == kWThreadErrorNone,
                "failed to create concurrent releasers");
        require(threadJoin(threads[0]) == 0 && threadJoin(threads[1]) == 0, "failed to join concurrent releasers");
        requireClosed(sockets[0]);
        close(sockets[1]);
        require(masterpoolGetCheckedOut(env->descriptors.master) == 0, "foreign release did not return the pooled box");
    }
    int sockets[2];
    require(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0, "failed to create foreign-acquisition sockets");
    const uint32_t   cached = env->descriptors.pool->len;
    foreign_create_t create = {.fd = sockets[0]};
    wthread_t        thread;
    require(threadCreate(&thread, createHandle, &create) == kWThreadErrorNone && threadJoin(thread) == 0,
            "foreign descriptor acquisition failed");
    require(env->descriptors.pool->len == cached && wiofdGetRefCount(create.handle) == 1,
            "foreign acquisition touched the worker-local pool");
    wiofdUnref(create.handle);
    requireClosed(sockets[0]);
    close(sockets[1]);
}

static int    callback_fd;
static wio_t *callback_io;
static void   freeInClose(wio_t *io)
{
    const int fd = wioGetFD(io);
    wioFree(io);
    require(wioGetFD(io) == fd && fcntl(fd, F_GETFD) >= 0, "close callback lost its descriptor too early");
    require(wioGet(io->loop, fd) == NULL, "closing WIO was reinitialized inside its callback");
    callback_io = wioGet(io->loop, callback_fd);
    require(callback_io != NULL && callback_io != io, "closing WIO was pooled before its callback returned");
}

static void testCloseCallback(test_env_t *env)
{
    int    sockets[2], other[2];
    wio_t *io = socketIO(env, sockets);
    require(socketpair(AF_UNIX, SOCK_STREAM, 0, other) == 0, "failed to create callback sockets");
    callback_fd = other[0];
    wioSetCallBackClose(io, freeInClose);
    wioClose(io);
    requireClosed(sockets[0]);
    require(fcntl(other[0], F_GETFD) >= 0, "outer close closed the callback's new socket");
    wioClose(callback_io);
    close(sockets[1]);
    close(other[1]);
}

static void testOutliveLocalPool(test_env_t *env)
{
    int       sockets[2];
    wio_t    *io     = socketIO(env, sockets);
    wio_fd_t *handle = wioGetFDHandle(io);
    wiofdRef(handle);
    wioClose(io);
    env->registry.slots[0].wio_fd_pool = NULL;
    genericpoolDestroy(env->descriptors.pool);
    env->descriptors.pool = NULL;
    wthread_t thread;
    require(threadCreate(&thread, releaseHandle, handle) == kWThreadErrorNone && threadJoin(thread) == 0,
            "failed to release a descriptor after its local pool was destroyed");
    requireClosed(sockets[0]);
    close(sockets[1]);
    require(masterpoolGetCheckedOut(env->descriptors.master) == 0, "late descriptor release missed the shared master");
    env->descriptors.pool = wiofdCreatePool(env->descriptors.master, 8);
    require(env->descriptors.pool != NULL, "failed to restore test descriptor pool");
    env->registry.slots[0].wio_fd_pool = env->descriptors.pool;
}

static void testPipeDescriptorZero(void)
{
#if WW_HAVE_SPLICE
    pid_t child = fork();
    require(child >= 0, "failed to fork descriptor-zero test");
    if (child == 0)
    {
        test_env_t env;
        setup(&env);
        int    sockets[2];
        wio_t *io = socketIO(&env, sockets);
        close(STDIN_FILENO);
        require(wioInitPipe(io) == 0 && io->fd_handle->pipefd[0] == STDIN_FILENO,
                "pipe initializer failed with descriptor zero");
        wioClose(io);
        requireClosed(STDIN_FILENO);
        close(sockets[1]);
        teardown(&env);
        _Exit(0);
    }
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
            "descriptor-zero test failed");
#endif
}

int main(void)
{
    testPipeDescriptorZero();
    test_env_t env;
    setup(&env);
    testRetainedDescriptors(&env);
    testNoClose(&env);
    testForeignReferences(&env);
    testCloseCallback(&env);
    testOutliveLocalPool(&env);
    teardown(&env);
    return 0;
}
