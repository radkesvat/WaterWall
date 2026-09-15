#include "buffer_queue.h"
#include "loggers/internal_logger.h"
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

static void setupWithBufferSize(test_env_t *env, uint32_t large_size)
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
    env->buffers = bufferpoolCreate(env->masters[0], env->masters[1], env->masters[2], 4, large_size, 1024);
    env->wios    = threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(env->masters[3], sizeof(wio_t), 4);
    require(env->buffers != NULL && env->wios != NULL, "failed to create test pools");
    env->wio_pools[0]          = env->wios;
    GSTATE.shortcut_wios_pools = env->wio_pools;
    env->loop                  = wloopCreate(WLOOP_FLAG_RUN_ONCE, env->buffers, 0);
    require(env->loop != NULL, "failed to create test loop");
}

static void setup(test_env_t *env)
{
    setupWithBufferSize(env, 4096);
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

typedef struct pending_reuse_probe_s
{
    test_env_t  *env;
    unsigned int reads;
} pending_reuse_probe_t;

static void unexpectedPendingRead(wio_t *io)
{
    discard io;
    require(false, "a closed descriptor's stale event reached its callback");
}

static void readReusedDescriptor(wio_t *io, sbuf_t *buf)
{
    pending_reuse_probe_t *probe = weventGetUserdata(io);
    require(sbufGetLength(buf) == 1 && sbufReadUI8(buf) == 'r', "reused descriptor delivered the wrong payload");
    ++probe->reads;
    bufferpoolReuseBuffer(probe->env->buffers, buf);

    const size_t checked_out = masterpoolGetCheckedOut(probe->env->masters[3]);
    wioFree(io);
    require(io->destroy && io->pending && io->fd_handle == NULL,
            "free from a read callback lost its pending allocation protection");
    require(masterpoolGetCheckedOut(probe->env->masters[3]) == checked_out,
            "read callback returned its WIO to the pool before dispatch finished");
}

static void testPendingDescriptorReuse(void)
{
    test_env_t env;
    setup(&env);
    // Drive two loops on one test thread to force destination dispatch before
    // the source loop finishes its stale pending entry, without a timing race.
    wloop_t *destination = wloopCreate(WLOOP_FLAG_RUN_ONCE, env.buffers, 0);
    require(destination != NULL, "failed to create the destination loop");
    const size_t baseline = masterpoolGetCheckedOut(env.masters[3]);
    int          sockets[2], replacement[2];
    wio_t       *old = socketIO(&env, sockets);
    require(socketpair(AF_UNIX, SOCK_STREAM, 0, replacement) == 0, "failed to prepare the replacement connection");
    require(wioAdd(old, unexpectedPendingRead, WW_READ) == 0, "failed to register the original descriptor");
    old->revents = WW_READ;
    EVENT_PENDING(old);
    require(wioClose(old) == 0 && old->pending, "closing a pending WIO lost its pending membership");
    require(dup2(replacement[0], sockets[0]) == sockets[0], "failed to force descriptor-number reuse");
    close(replacement[0]);

    wio_t *fresh = wioGet(env.loop, sockets[0]);
    require(fresh != NULL && wioIsOpened(fresh) && fresh != old && ! fresh->pending,
            "descriptor reuse inherited the old WIO's pending entry");
    require(old->destroy && old->pending && old->loop == env.loop && old->fd_handle == NULL,
            "retired WIO did not remain owned by its original pending list");
    wioDetach(fresh);
    wioAttach(destination, fresh);
    pending_reuse_probe_t probe = {.env = &env};
    weventSetUserData(fresh, &probe);
    wioSetCallBackRead(fresh, readReusedDescriptor);
    require(wioRead(fresh) == 0 && send(replacement[1], "r", 1, 0) == 1,
            "failed to make the transferred connection readable");
    require(wloopProcessEvents(destination, 0) >= 0 && probe.reads == 1 && destination->npendings == 0,
            "the transferred connection was stranded by stale pending membership");
    require(! wioExists(destination, sockets[0]), "callback-freed WIO remained in the destination table");
    require(old->pending && old->loop == env.loop, "destination dispatch altered the source's pending entry");
    require(wloopProcessEvents(env.loop, 0) >= 0 && env.loop->npendings == 0,
            "source loop did not settle the old pending entry");
    require(masterpoolGetCheckedOut(env.masters[3]) == baseline, "pending dispatch leaked or recycled a WIO twice");

    close(sockets[1]);
    close(replacement[1]);
    wloopDestroy(&destination);
    teardown(&env);
}

static void testPendingDetachRejected(void)
{
    pid_t child = fork();
    require(child >= 0, "failed to fork pending-detach test");
    if (child == 0)
    {
        test_env_t env;
        setup(&env);
        int    sockets[2];
        wio_t *io = socketIO(&env, sockets);
        require(wioAdd(io, unexpectedPendingRead, WW_READ) == 0, "failed to register pending-detach descriptor");
        EVENT_PENDING(io);
        require(wioReadStop(io) == 0, "failed to stop pending-detach read interest");
        wioDetach(io);
        _Exit(0);
    }
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 1,
            "pending detach was not rejected before handoff");
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

#if WW_HAVE_SPLICE
typedef enum splice_case_e
{
    kSpliceConvertFD,
    kSpliceConvertPipe,
    kSplicePartialFD,
    kSplicePartialPipe,
    kSpliceRetainPipe,
    kSpliceDisabled,
    kSpliceHeldReservation,
    kSpliceDroppedReservation,
    kSpliceClosedReservation,
    kSplicePartialReservation,
    kSpliceSmallDestination,
    kSplicePartialRange,
    kSplicePartialCapacity,
    kSpliceShortFD,
    kSpliceShortPipe,
    kSpliceShortPartial,
    kSpliceFailedRead,
    kSpliceInvalidFlags,
    kSpliceMissingPipe,
    kSpliceMissingReservation,
    kSpliceMoveTwice,
    kSpliceWriteGuard,
    kSpliceQueueGuard
} splice_case_t;

typedef struct splice_probe_s
{
    test_env_t   *env;
    splice_case_t kind;
    uint8_t       data[LARGE_BUFFER_SIZE_RAM_HIGH + 17];
    uint32_t      length;
    uint32_t      received;
    unsigned int  calls;
    unsigned int  closes;
    sbuf_t       *held;
    wio_fd_t     *retained;
} splice_probe_t;

static void spliceClosed(wio_t *io)
{
    splice_probe_t *probe = weventGetUserdata(io);
    ++probe->closes;
}

static void requireSplicePayload(splice_probe_t *probe, sbuf_t *buf, uint32_t body_bytes, bool appended)
{
    const uint32_t prefix = appended ? 6 : 4;
    require(sbufGetLength(buf) == body_bytes + prefix && buf->flags == 0,
            "splice conversion returned invalid length or flags");
    require(memoryEqual(sbufGetRawPtr(buf), appended ? ">>HEAD" : "HEAD", prefix) &&
                memoryEqual(sbufGetMutablePtr(buf) + prefix, probe->data + probe->received, body_bytes),
            "splice conversion lost prefix bytes or changed payload order");
    require(buf->curpos == (appended ? 64 : 60) && sbufGetLeftPadding(buf) == 64,
            "splice conversion changed the expected padding layout");
}

static void spliceRead(wio_t *io, sbuf_t *buf)
{
    splice_probe_t *probe = weventGetUserdata(io);
    buffer_pool_t  *pool  = probe->env->buffers;
    const uint32_t  count = sbufGetLength(buf);
    ++probe->calls;
    if (probe->kind == kSpliceDisabled)
    {
        require(buf->flags == 0 && count <= probe->length - probe->received &&
                    memoryEqual(sbufGetRawPtr(buf), probe->data + probe->received, count),
                "disabled splice mode did not deliver ordinary bytes");
        probe->received += count;
        bufferpoolReuseBuffer(pool, buf);
        return;
    }

    const uint32_t limit = min(bufferpoolGetLargeBufferSize(pool), (uint32_t) LARGE_BUFFER_SIZE_RAM_HIGH);
    require(count == min(probe->length - probe->received, limit) && count > 0,
            "splice dispatch used the wrong availability count or cap");
    require(buf->flags == (kSbufFlagSplice | kSbufFlagSpliceFD) && buf->curpos == 64 && buf->capacity == 64 + count &&
                sbufGetLifetime(buf) == NULL,
            "splice dispatch supplied an invalid wrapper");
    wio_fd_t *handle;
    sbufByteCopy(&handle, buf->buf + sbufGetLeftPadding(buf), sizeof(handle));
    require(handle == wioGetFDHandle(io) && handle->reserved == count && wiofdGetRefCount(handle) == 2,
            "splice callback did not receive a reserved, retained descriptor");

    switch (probe->kind)
    {
    case kSpliceHeldReservation:
        probe->held = buf;
        return;
    case kSpliceDroppedReservation:
        bufferpoolReuseBuffer(pool, buf);
        return;
    case kSpliceClosedReservation:
        bufferpoolReuseBuffer(pool, buf);
        wioFree(io);
        return;
    case kSplicePartialReservation: {
        sbuf_t *dest = bufferpoolGetLargeBuffer(pool);
        wioPartialReadSpliceBuffer(buf, dest, 1);
        bufferpoolReuseBuffer(pool, dest);
        bufferpoolReuseBuffer(pool, buf);
        return;
    }
    case kSpliceSmallDestination:
        wioTransformSpliceBufferToRealBuffer(buf, sbufCreateWithPadding(0, 64), pool);
        break;
    case kSplicePartialRange:
        wioPartialReadSpliceBuffer(buf, bufferpoolGetLargeBuffer(pool), count + 1);
        break;
    case kSplicePartialCapacity: {
        sbuf_t *dest = bufferpoolGetLargeBuffer(pool);
        sbufSetLength(dest, sbufGetMaximumWriteableSize(dest));
        wioPartialReadSpliceBuffer(buf, dest, 1);
        break;
    }
    case kSpliceShortFD:
    case kSpliceShortPipe:
    case kSpliceShortPartial:
        if (probe->kind == kSpliceShortPipe)
        {
            wioMoveSpliceBuferToPipe(buf);
        }
        else
        {
            ++handle->reserved;
        }
        ++buf->capacity;
        sbufSetLength(buf, count + 1);
        if (probe->kind == kSpliceShortPartial)
        {
            wioPartialReadSpliceBuffer(buf, bufferpoolGetLargeBuffer(pool), count + 1);
        }
        else
        {
            wioTransformSpliceBufferToRealBuffer(buf, bufferpoolGetLargeBuffer(pool), pool);
        }
        break;
    case kSpliceFailedRead: {
        uint8_t drained[32];
        require(count <= sizeof(drained) && recv(handle->fd, drained, count, 0) == (ssize_t) count,
                "failed to drain socket for EAGAIN fixture");
        wioTransformSpliceBufferToRealBuffer(buf, bufferpoolGetLargeBuffer(pool), pool);
        break;
    }
    case kSpliceInvalidFlags:
        buf->flags |= kSbufFlagSplicePiped;
        wioPartialReadSpliceBuffer(buf, bufferpoolGetLargeBuffer(pool), 1);
        break;
    case kSpliceMissingPipe:
        close(handle->pipefd[0]);
        close(handle->pipefd[1]);
        handle->pipefd[0] = handle->pipefd[1] = 0;
        wioMoveSpliceBuferToPipe(buf);
        break;
    case kSpliceMissingReservation:
        --handle->reserved;
        wioPartialReadSpliceBuffer(buf, bufferpoolGetLargeBuffer(pool), count);
        break;
    case kSpliceMoveTwice:
        wioMoveSpliceBuferToPipe(buf);
        wioMoveSpliceBuferToPipe(buf);
        break;
    case kSpliceWriteGuard:
        wioWrite(io, buf);
        break;
    case kSpliceQueueGuard: {
        buffer_queue_t queue = bufferqueueCreate(1);
        bufferqueuePushBack(&queue, buf);
        break;
    }
    default:
        break;
    }
    require(probe->kind <= kSpliceDisabled, "a splice failure case returned instead of aborting");

    sbufShiftLeft(buf, 4);
    sbufWrite(buf, "HEAD", 4);
    const bool piped =
        probe->kind == kSpliceConvertPipe || probe->kind == kSplicePartialPipe || probe->kind == kSpliceRetainPipe;
    if (piped)
    {
        require(wioMoveSpliceBuferToPipe(buf) == (ssize_t) count && handle->reserved == 0 &&
                    buf->flags == (kSbufFlagSplice | kSbufFlagSplicePiped),
                "moving to the pipe changed the wrong flags or reservation");
    }
    if (probe->kind == kSpliceRetainPipe)
    {
        wiofdRef(handle);
        probe->retained = handle;
        probe->held     = buf;
        probe->received += count;
        wioFree(io);
        return;
    }

    const bool partial = probe->kind == kSplicePartialFD || probe->kind == kSplicePartialPipe;
    sbuf_t    *dest    = bufferpoolGetLargeBuffer(pool);
    if (partial)
    {
        sbufSetLength(dest, 2);
        sbufWrite(dest, ">>", 2);
        require(wioPartialReadSpliceBuffer(buf, dest, 0) == dest && sbufGetLength(dest) == 2 &&
                    sbufGetLength(buf) == count + 4,
                "zero-byte partial read changed either buffer");
        wioPartialReadSpliceBuffer(buf, dest, 2);
        require(buf->curpos == 62 && handle->reserved == (piped ? 0 : count), "prefix-only read consumed socket bytes");
        wioPartialReadSpliceBuffer(buf, dest, 4);
        require(buf->curpos == 64 && buf->capacity == 64 + count - 2 && sbufGetLength(buf) == count - 2 &&
                    handle->reserved == (piped ? 0 : count - 2),
                "mixed prefix/body read left incorrect source accounting");
        wioPartialReadSpliceBuffer(buf, dest, sbufGetLength(buf));
        require(sbufGetLength(buf) == 0 && buf->curpos == 64 && buf->capacity == 64 &&
                    buf->flags == (kSbufFlagSplice | (piped ? kSbufFlagSplicePiped : kSbufFlagSpliceFD)),
                "full partial-read consumption did not leave a reusable empty wrapper");
        bufferpoolReuseBuffer(pool, buf);
    }
    else
    {
        require(wioTransformSpliceBufferToRealBuffer(buf, dest, pool) == dest,
                "full conversion did not return caller-supplied storage");
    }
    require(handle->reserved == 0, "splice consumption did not settle its reservation");
    requireSplicePayload(probe, dest, count, partial);
    probe->received += count;
    bufferpoolReuseBuffer(pool, dest);
}

static void runSpliceCase(splice_case_t kind, uint32_t large_size, uint32_t length)
{
    test_env_t env;
    setupWithBufferSize(&env, large_size);
    bufferpoolUpdateAllocationPaddings(env.buffers, 64, 64, 64);
    int            sockets[2];
    wio_t         *io    = socketIO(&env, sockets);
    splice_probe_t probe = {.env = &env, .kind = kind, .length = length};
    require(length <= sizeof(probe.data), "splice fixture payload is too large");
    for (uint32_t i = 0; i < length; ++i)
    {
        probe.data[i] = (uint8_t) (i * 17U + 3U);
    }
    weventSetUserData(io, &probe);
    wioSetCallBackRead(io, spliceRead);
    wioSetCallBackClose(io, spliceClosed);
    if (kind != kSpliceDisabled)
    {
        require(wioEnableSplice(io) == 0, "failed to enable splice in fixture");
    }
    require(wioRead(io) == 0, "failed to start splice fixture reads");
    // No data and no EOF: zero availability must not fabricate a splice wrapper.
    io->revents = WW_READ;
    EVENT_PENDING(io);
    require(wloopProcessEvents(env.loop, 0) >= 0 && probe.calls == 0 && ! io->closed,
            "spurious readiness fabricated payload or closed a live socket");
    require(send(sockets[1], probe.data, length, 0) == (ssize_t) length, "failed to queue splice fixture bytes");
    for (unsigned int attempt = 0; attempt < 8 && probe.received < length; ++attempt)
    {
        require(wloopProcessEvents(env.loop, 0) >= 0, "splice fixture dispatch failed");
    }
    require(probe.received == length, "splice dispatch did not consume all queued bytes");
    if (kind == kSpliceRetainPipe)
    {
        require(probe.closes == 1 && probe.held != NULL && wiofdGetRefCount(probe.retained) == 1,
                "pipe-backed wrapper did not outlive WIO close with its caller-owned reference");
        sbuf_t *dest = bufferpoolGetLargeBuffer(env.buffers);
        wioTransformSpliceBufferToRealBuffer(probe.held, dest, env.buffers);
        probe.received = 0;
        requireSplicePayload(&probe, dest, length, false);
        bufferpoolReuseBuffer(env.buffers, dest);
        wiofdUnref(probe.retained);
        requireClosed(sockets[0]);
        close(sockets[1]);
    }
    else
    {
        close(sockets[1]);
        require(wloopProcessEvents(env.loop, 0) >= 0 && probe.closes == 1 && wioIsClosed(io),
                "zero availability at EOF failed to close the connection");
    }
    teardown(&env);
}

static void testSpliceReads(void)
{
    runSpliceCase(kSpliceConvertFD, 4096, 4097);
    runSpliceCase(kSpliceConvertFD, 65536, LARGE_BUFFER_SIZE_RAM_HIGH + 17);
    runSpliceCase(kSpliceConvertPipe, 4096, 9);
    runSpliceCase(kSplicePartialFD, 4096, 9);
    runSpliceCase(kSplicePartialPipe, 4096, 9);
    runSpliceCase(kSpliceRetainPipe, 4096, 9);
    runSpliceCase(kSpliceDisabled, 4096, 9);

    const struct
    {
        splice_case_t kind;
        const char   *diagnostic;
    } failures[] = {
        {kSpliceHeldReservation, "splice callback returned with unconsumed socket bytes"},
        {kSpliceDroppedReservation, "splice callback returned with unconsumed socket bytes"},
        {kSpliceClosedReservation, "splice callback returned with unconsumed socket bytes"},
        {kSplicePartialReservation, "splice callback returned with unconsumed socket bytes"},
        {kSpliceSmallDestination, "destination too small"},
        {kSplicePartialRange, "requested bytes or prefix exceed source length"},
        {kSplicePartialCapacity, "destination has insufficient append space"},
        {kSpliceShortFD, "incomplete read from source fd (requested=10, result=9"},
        {kSpliceShortPipe, "incomplete read from pipe (requested=10, result=9"},
        {kSpliceShortPartial, "incomplete read from source fd (requested=10, result=9"},
        {kSpliceFailedRead, "incomplete read from source fd (requested=9, result=-1"},
        {kSpliceInvalidFlags, "requires exactly one of SpliceFD and SplicePiped"},
        {kSpliceMissingPipe, "descriptor pipe must already be initialized"},
        {kSpliceMissingReservation, "source reservation is too small"},
        {kSpliceMoveTwice, "with kSbufFlagSplicePiped clear"},
        {kSpliceWriteGuard, "splice buffer sending is not implemented"},
        {kSpliceQueueGuard, "splice buffer storage is not implemented"},
    };
    for (size_t i = 0; i < ARRAY_SIZE(failures); ++i)
    {
        int output[2];
        require(pipe(output) == 0, "failed to create fatal-diagnostic pipe");
        pid_t child = fork();
        require(child >= 0, "failed to fork splice fatal-path test");
        if (child == 0)
        {
            close(output[0]);
            require(dup2(output[1], STDERR_FILENO) == STDERR_FILENO, "failed to redirect fatal diagnostic");
            close(output[1]);
            require(createInternalLogger(NULL, true) != NULL, "failed to create fatal-path logger");
            runSpliceCase(failures[i].kind, 4096, 9);
            _Exit(66);
        }
        close(output[1]);
        char    diagnostic[4096];
        size_t  used = 0;
        ssize_t count;
        while (used < sizeof(diagnostic) - 1 &&
               (count = read(output[0], diagnostic + used, sizeof(diagnostic) - 1 - used)) != 0)
        {
            if (count < 0 && errno == EINTR)
            {
                continue;
            }
            require(count > 0, "failed to read fatal diagnostic");
            used += (size_t) count;
        }
        diagnostic[used] = '\0';
        close(output[0]);
        int status;
        require(waitpid(child, &status, 0) == child, "failed to join splice fatal-path child");
        if (! WIFEXITED(status) || WEXITSTATUS(status) != 1 || strstr(diagnostic, failures[i].diagnostic) == NULL)
        {
            fprintf(stderr,
                    "splice fatal case %d: expected '%s', status=%d, got: %s\n",
                    (int) failures[i].kind,
                    failures[i].diagnostic,
                    status,
                    diagnostic);
            exit(1);
        }
    }
}
#endif

int main(void)
{
    testPipeDescriptorZero();
    testPendingDescriptorReuse();
    testPendingDetachRejected();
#if WW_HAVE_SPLICE
    testSpliceReads();
#endif
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
