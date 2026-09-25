#include "buffer_queue.h"
#include "loggers/internal_logger.h"
#include "splice_buffer.h"
#include "threadsafe_generic_pool.h"
#include "wevent.h"
#include "worker_registry_fixture.h"

#include <fcntl.h>
#include <netinet/tcp.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct test_env_s
{
    test_worker_registry_t     registry;
    master_pool_t             *masters[5];
    buffer_pool_t             *buffers;
    buffer_pool_t             *buffer_pools[1];
    threadsafe_generic_pool_t *wios;
    threadsafe_generic_pool_t *wio_pools[1];
    wloop_t                   *loop;
} test_env_t;

#if WW_HAVE_SPLICE
static unsigned int splice_reuse_checks;
bool                __real_sbufSpliceIsReusable(const sbuf_t *buf);
bool                __wrap_sbufSpliceIsReusable(const sbuf_t *buf);

bool __wrap_sbufSpliceIsReusable(const sbuf_t *buf)
{
    ++splice_reuse_checks;
    return __real_sbufSpliceIsReusable(buf);
}

static bool fail_queue_allocation;
void       *__real_memoryReAllocate(void *ptr, size_t size);
void       *__wrap_memoryReAllocate(void *ptr, size_t size);

void *__wrap_memoryReAllocate(void *ptr, size_t size)
{
    if (fail_queue_allocation)
    {
        fail_queue_allocation = false;
        return NULL;
    }
    return __real_memoryReAllocate(ptr, size);
}

static bool         fail_pipe;
static unsigned int pipe_calls;
static bool         mock_pipe_capacity;
static int          pipe_capacity = 65536, pipe_query_error, pipe_growth_error, pipe_requested_capacity;
static unsigned int pipe_query_calls, pipe_growth_calls;
static bool         mock_pipe_time;
static uint64_t     pipe_time_us;
static unsigned int pipe_time_calls;
unsigned long long  __real_getHRTimeUs(void);
unsigned long long  __wrap_getHRTimeUs(void);

unsigned long long __wrap_getHRTimeUs(void)
{
    if (mock_pipe_time)
    {
        ++pipe_time_calls;
        return pipe_time_us;
    }
    return __real_getHRTimeUs();
}

int __real_fcntl(int fd, int command, ...);
int __wrap_fcntl(int fd, int command, ...);

int __wrap_fcntl(int fd, int command, ...)
{
    switch (command)
    {
    case F_GETPIPE_SZ:
        ++pipe_query_calls;
        if (mock_pipe_capacity)
        {
            if (pipe_query_error != 0)
            {
                errno = pipe_query_error;
                return -1;
            }
            return pipe_capacity;
        }
        return __real_fcntl(fd, command);
    case F_GETFD:
    case F_GETFL:
        return __real_fcntl(fd, command);
    case F_SETPIPE_SZ:
    case F_SETFD:
    case F_SETFL: {
        va_list args;
        va_start(args, command);
        int value = va_arg(args, int);
        va_end(args);
        if (command == F_SETPIPE_SZ)
        {
            ++pipe_growth_calls;
            pipe_requested_capacity = value;
            if (mock_pipe_capacity)
            {
                if (pipe_growth_error != 0)
                {
                    errno = pipe_growth_error;
                    return -1;
                }
                return pipe_capacity = value;
            }
        }
        return __real_fcntl(fd, command, value);
    }
    default:
        fprintf(stderr, "unexpected fcntl command in pipe fixture: %d\n", command);
        abort();
    }
}

static int          read_test_fd      = -1, splice_read_error;
static size_t       splice_read_limit = SIZE_MAX;
static bool         splice_read_eof;
static unsigned int splice_read_calls;
static size_t       splice_read_requested;
static unsigned int socket_read_queries;
int                 __real_ioctl(int fd, unsigned long request, ...);
int                 __wrap_ioctl(int fd, unsigned long request, ...);

int __wrap_ioctl(int fd, unsigned long request, ...)
{
    va_list args;
    va_start(args, request);
    void *arg = va_arg(args, void *);
    va_end(args);
    if (fd == read_test_fd && request == FIONREAD)
        ++socket_read_queries;
    return __real_ioctl(fd, request, arg);
}

static int          last_splice_read_pipe = -1;
static wloop_t     *quiesce_after_splice_read;
static int          pipe_read_fd    = -1, pipe_read_error;
static size_t       pipe_read_limit = SIZE_MAX;
static unsigned int pipe_read_calls, pipe_read_error_after;
ssize_t             __real_read(int fd, void *buf, size_t count);
ssize_t             __wrap_read(int fd, void *buf, size_t count);
ssize_t             __wrap_read(int fd, void *buf, size_t count)
{
    if (fd == pipe_read_fd)
    {
        if (pipe_read_calls++ >= pipe_read_error_after && pipe_read_error != 0)
        {
            errno           = pipe_read_error;
            pipe_read_error = 0;
            return -1;
        }
        count = min(count, pipe_read_limit);
    }
    return __real_read(fd, buf, count);
}
static int    write_test_fd = -1;
static size_t send_limit = SIZE_MAX, splice_limit = SIZE_MAX;
static int    send_error, splice_error;
ssize_t       __real_send(int fd, const void *buf, size_t len, int flags);
ssize_t       __wrap_send(int fd, const void *buf, size_t len, int flags);
ssize_t       __real_splice(int in, off_t *in_offset, int out, off_t *out_offset, size_t len, unsigned int flags);
ssize_t       __wrap_splice(int in, off_t *in_offset, int out, off_t *out_offset, size_t len, unsigned int flags);
int         __real_pipe2(int pipefd[2], int flags);
int         __wrap_pipe2(int pipefd[2], int flags);

int __wrap_pipe2(int pipefd[2], int flags)
{
    ++pipe_calls;
    if (fail_pipe)
    {
        fail_pipe = false;
        errno     = EMFILE;
        return -1;
    }
    return __real_pipe2(pipefd, flags);
}

ssize_t __wrap_send(int fd, const void *buf, size_t len, int flags)
{
    if (fd == write_test_fd)
    {
        if (send_error != 0)
        {
            errno      = send_error;
            send_error = 0;
            return -1;
        }
        len = min(len, send_limit);
    }
    return __real_send(fd, buf, len, flags);
}

ssize_t __wrap_splice(int in, off_t *in_offset, int out, off_t *out_offset, size_t len, unsigned int flags)
{
    if (in == read_test_fd)
    {
        ++splice_read_calls;
        splice_read_requested = len;
        last_splice_read_pipe = out;
        if (splice_read_error != 0)
        {
            errno             = splice_read_error;
            splice_read_error = 0;
            return -1;
        }
        if (splice_read_eof)
        {
            splice_read_eof = false;
            return 0;
        }
        const ssize_t moved = __real_splice(in, in_offset, out, out_offset, min(len, splice_read_limit), flags);
        if (moved > 0 && quiesce_after_splice_read != NULL)
        {
            wloopRequestQuiesce(quiesce_after_splice_read);
            quiesce_after_splice_read = NULL;
        }
        return moved;
    }
    if (out == write_test_fd)
    {
        if (splice_error != 0)
        {
            errno        = splice_error;
            splice_error = 0;
            return -1;
        }
        len = min(len, splice_limit);
    }
    return __real_splice(in, in_offset, out, out_offset, len, flags);
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
    for (size_t i = 0; i < ARRAY_SIZE(env->masters); ++i)
    {
        env->masters[i] = masterpoolCreateWithCapacity(8);
        require(env->masters[i] != NULL, "failed to create test master pool");
    }
    env->buffers =
        bufferpoolCreate(env->masters[0],
                         env->masters[4],
                         env->masters[1],
                         env->masters[2],
                         4,
                         large_size,
                         MEDIUM_BUFFER_SIZE_RAM_HIGH,
                         1024,
                         large_size >= LARGE_BUFFER_SIZE_RAM_LOW ? SPLICE_PAYLOAD_LIMIT : large_size,
                         max((uint32_t) (large_size),
                             (uint32_t) (large_size >= LARGE_BUFFER_SIZE_RAM_LOW ? SPLICE_PAYLOAD_LIMIT : large_size)));
    env->wios    = threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(env->masters[3], sizeof(wio_t), 4);
    require(env->buffers != NULL && env->wios != NULL, "failed to create test pools");
    require(bufferpoolGetSplicePayloadLimit(env->buffers) ==
                (large_size >= LARGE_BUFFER_SIZE_RAM_LOW ? SPLICE_PAYLOAD_LIMIT : large_size),
            "pool lost explicit splice setting, including on unsupported builds");
    env->buffer_pools[0]         = env->buffers;
    GSTATE.shortcut_buffer_pools = env->buffer_pools;
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
    require(masterpoolGetCheckedOut(env->masters[3]) == 0, "loop cleanup retained a live WIO allocation");
    GSTATE.shortcut_wios_pools = NULL;
    threadsafegenericpoolDestroy(env->wios);
    bufferpoolDestroy(env->buffers);
    GSTATE.shortcut_buffer_pools = NULL;
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
    require(wioGetFD(io) == sockets[0], "new WIO did not adopt its descriptor");
    return io;
}

static void testOwnedDescriptor(test_env_t *env)
{
    int       sockets[2];
    wio_t    *io     = socketIO(env, sockets);
#if WW_HAVE_SPLICE
    sbuf_t *pipe_buf = sbufCreateSplice(0);
    fail_pipe = true;
    require(sbufSpliceInitPipe(pipe_buf, 0) == -1 && errno == EMFILE, "pipe failure did not propagate");
    require(sbufSpliceInitPipe(pipe_buf, 0) == 0, "pipe creation failed");
    const int reader = sbufSpliceMetadata(pipe_buf).pipefd[0];
    const int writer = sbufSpliceMetadata(pipe_buf).pipefd[1];
    require(sbufSpliceInitPipe(pipe_buf, 0) == 0 && sbufSpliceMetadata(pipe_buf).pipefd[0] == reader &&
                sbufSpliceMetadata(pipe_buf).pipefd[1] == writer,
            "repeated pipe initialization replaced live descriptors");
    require((fcntl(reader, F_GETFL) & O_NONBLOCK) && (fcntl(writer, F_GETFL) & O_NONBLOCK), "splice pipe is blocking");
    require((fcntl(reader, F_GETFD) & FD_CLOEXEC) && (fcntl(writer, F_GETFD) & FD_CLOEXEC),
            "splice pipe is inheritable across exec");
#else
    require(wioEnableSplice(io) == -1 && errno == ENOSYS, "unsupported splice mode did not fail");
    sbuf_t *unsupported = sbufCreateSplice(0);
    require(sbufSpliceInitPipe(unsupported, 0) == -1 && errno == ENOSYS, "unsupported pipe initialization succeeded");
    sbufDestroySplice(unsupported);
    for (unsigned int i = 0; i < 2; ++i)
        require(bufferpoolGetSpliceBuffer(env->buffers) == NULL && errno == ENOSYS,
                "unsupported splice checkout did not return ENOSYS");
#endif
    require(wioClose(io) == 0 && wioGetFD(io) == -1, "WIO close did not invalidate its descriptor");
    require(wioAdd(io, NULL, WW_READ) == -1, "closed WIO accepted new watcher interest");
    requireClosed(sockets[0]);
#if WW_HAVE_SPLICE
    char byte = 'x';
    require(write(writer, &byte, 1) == 1 && read(reader, &byte, 1) == 1, "retained pipe stopped working");
    sbufDestroySplice(pipe_buf);
    requireClosed(reader);
    requireClosed(writer);
#endif

    require(dup2(sockets[1], sockets[0]) == sockets[0], "failed to reuse descriptor number");
    require(wioClose(io) == 0 && fcntl(sockets[0], F_GETFD) >= 0, "repeated close affected a reused descriptor");
    wio_t *reused = wioGet(env->loop, sockets[0]);
    require(reused == io && wioGetFD(reused) == sockets[0], "closed WIO was not reusable");
    wioClose(reused);
    close(sockets[1]);
}

static void testNoClose(test_env_t *env)
{
    int    sockets[2];
    wio_t *io = socketIO(env, sockets);
#if WW_HAVE_SPLICE
    sbuf_t *pipe_buf = sbufCreateSplice(0);
    require(sbufSpliceInitPipe(pipe_buf, 0) == 0, "failed to create no-close pipe");
    int reader = sbufSpliceMetadata(pipe_buf).pipefd[0], writer = sbufSpliceMetadata(pipe_buf).pipefd[1];
#endif
    wioReleaseNoClose(io);
    require(! wioExists(env->loop, sockets[0]), "watcher release retained its array slot");
    require(fcntl(sockets[0], F_GETFD) >= 0, "watcher release closed the external descriptor");
#if WW_HAVE_SPLICE
    sbufDestroySplice(pipe_buf);
    requireClosed(reader);
    requireClosed(writer);
#endif
    char byte = 'x';
    require(send(sockets[0], &byte, 1, 0) == 1 && recv(sockets[1], &byte, 1, 0) == 1,
            "released external socket stopped working");
    close(sockets[0]);
    close(sockets[1]);
}

static void testFileDescriptor(test_env_t *env)
{
    int pair[2];
    require(pipe(pair) == 0, "failed to create a non-socket descriptor");
    wio_t *io = wioGet(env->loop, pair[0]);
    require(io != NULL && wioGetFD(io) == pair[0] && ! (wioGetType(io) & WIO_TYPE_SOCKET),
            "non-socket descriptor was not adopted correctly");
    wioClose(io);
    require(wioGetFD(io) == -1, "non-socket close retained the descriptor");
    requireClosed(pair[0]);
    require(fcntl(pair[1], F_GETFD) >= 0, "closing the reader closed an unrelated descriptor");
    close(pair[1]);
}

static void testPrimaryDescriptorZero(void)
{
    pid_t child = fork();
    require(child >= 0, "failed to fork primary descriptor-zero fixture");
    if (child == 0)
    {
        test_env_t env;
        setup(&env);
        close(STDIN_FILENO);
        int    sockets[2];
        wio_t *io = socketIO(&env, sockets);
        require(sockets[0] == STDIN_FILENO && wioGetFD(io) == STDIN_FILENO,
                "descriptor zero was treated as uninitialized");
        wioClose(io);
        require(wioGetFD(io) == -1, "descriptor-zero close failed to invalidate the WIO");
        requireClosed(STDIN_FILENO);
        close(sockets[1]);
        teardown(&env);
        _Exit(0);
    }
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
            "primary descriptor-zero fixture failed");
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
    require(io->destroy && io->pending && wioGetFD(io) == -1,
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
    require(old->destroy && old->pending && old->loop == env.loop && wioGetFD(old) == -1,
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
        sbuf_t *pipe_buf = sbufCreateSplice(0);
        close(STDIN_FILENO);
        require(sbufSpliceInitPipe(pipe_buf, 0) == 0 && sbufSpliceMetadata(pipe_buf).pipefd[0] == STDIN_FILENO,
                "pipe initializer failed with descriptor zero");
        wioClose(io);
        sbufDestroySplice(pipe_buf);
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
static void testPipeCapacityPreference(void)
{
    mock_pipe_time = true;
    pipe_time_us   = 10000000;
    const struct
    {
        uint32_t     preferred;
        int          initial, query_error, growth_error;
        unsigned int expected_growth;
    } cases[] = {
        {0, 65536, 0, 0, 0},
        {4096, 65536, 0, 0, 0},
        {512 * 1024, 65536, 0, 0, 1},
        {512 * 1024, 1024 * 1024, 0, 0, 0},
        {512 * 1024, 65536, 0, EPERM, 1},
        {512 * 1024, 65536, 0, ENOMEM, 1},
        {512 * 1024, 65536, 0, EINTR, 1},
        {512 * 1024, 65536, EINVAL, 0, 0},
    };
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        mock_pipe_capacity      = true;
        pipe_capacity           = cases[i].initial;
        pipe_query_error        = cases[i].query_error;
        pipe_growth_error       = cases[i].growth_error;
        pipe_query_calls        = 0;
        pipe_growth_calls       = 0;
        pipe_requested_capacity = 0;
        sbuf_t *buf             = sbufCreateSplice(0);
        require(sbufSpliceInitPipe(buf, cases[i].preferred) == 0, "capacity preference failure rejected a usable pipe");
        const splice_buffer_metadata_t metadata = sbufSpliceMetadata(buf);
        require(pipe_query_calls == (cases[i].preferred != 0) && pipe_growth_calls == cases[i].expected_growth,
                "pipe capacity query or growth had the wrong call count");
        require(! cases[i].expected_growth || pipe_requested_capacity == (int) cases[i].preferred,
                "pipe growth used the wrong requested size");
        require(sbufSpliceInitPipe(buf, cases[i].preferred) == 0 && pipe_growth_calls == cases[i].expected_growth &&
                    pipe_query_calls == (cases[i].preferred != 0),
                "repeated pipe initialization retried capacity negotiation");
        char byte = 0;
        require(write(metadata.pipefd[1], "x", 1) == 1 && read(metadata.pipefd[0], &byte, 1) == 1 && byte == 'x',
                "capacity negotiation left an unusable pipe");
        sbufDestroySplice(buf);
        requireClosed(metadata.pipefd[0]);
        requireClosed(metadata.pipefd[1]);
    }
    mock_pipe_capacity = false;
    pipe_query_error = pipe_growth_error = 0;
    mock_pipe_time                       = false;
}

static void testSpliceReuseValidation(void)
{
    test_env_t env;
    setup(&env);
    for (unsigned int length = 0; length <= 4; length += 4)
    {
        sbuf_t *buf = bufferpoolGetSpliceBuffer(env.buffers);
        require(buf != NULL, "could not check out recycle-check pipe");
        if (length != 0)
        {
            require(write(sbufSpliceMetadata(buf).pipefd[1], "data", length) == (ssize_t) length,
                    "could not fill recycle-check pipe");
            buf->capacity = (uint32_t) buf->l_pad + length;
            sbufSetLength(buf, length);
        }
        splice_reuse_checks = 0;
        bufferpoolReuseBuffer(env.buffers, buf);
#if BUFFER_POOL_DEBUG == 1
        require(splice_reuse_checks == 1, "pool debugging did not verify kernel emptiness");
#else
        require(splice_reuse_checks == 0, "pool return checked kernel emptiness with pool debugging disabled");
#endif
        buf = bufferpoolGetSpliceBuffer(env.buffers);
        require(sbufSpliceIsReusable(buf), "pool return failed to discard the private body");
        bufferpoolReuseBuffer(env.buffers, buf);
    }
    teardown(&env);
}

static void testPipeCapacityRetry(void)
{
    test_env_t env;
    setupWithBufferSize(&env, LARGE_BUFFER_SIZE_RAM_HIGH);
    mock_pipe_capacity = mock_pipe_time = true;
    pipe_time_us                        = 10000000;
    pipe_capacity                       = 65536;
    pipe_growth_error                   = EPERM;
    pipe_query_error                    = 0;
    pipe_query_calls = pipe_growth_calls = 0;
    const uint32_t     preferred         = SPLICE_PAYLOAD_LIMIT;
    const unsigned int initial_creates   = pipe_calls;
    sbuf_t            *buf               = bufferpoolGetSpliceBuffer(env.buffers);
    require(buf != NULL, "denied initial growth failed checkout");
    const splice_buffer_metadata_t initial = sbufSpliceMetadata(buf);
    require(initial.pipe_capacity == 65536 && initial.capacity_retry_at_us == pipe_time_us + 1000000,
            "denied growth did not record its capacity and one-second cooldown");

    // Repeated pool returns must retain both the pair and its retry deadline.
    for (unsigned int i = 0; i < 10; ++i)
    {
        pipe_time_us     = initial.capacity_retry_at_us - 1;
        sbuf_t *previous = buf;
        bufferpoolReuseBuffer(env.buffers, buf);
        buf = bufferpoolGetSpliceBuffer(env.buffers);
        require(buf == previous, "retry fixture did not reuse its pooled wrapper");
        const splice_buffer_metadata_t metadata = sbufSpliceMetadata(buf);
        require(metadata.pipefd[0] == initial.pipefd[0] && metadata.pipefd[1] == initial.pipefd[1] &&
                    metadata.capacity_retry_at_us == initial.capacity_retry_at_us,
                "pool reuse lost pipe ownership or reset its cooldown");
    }
    require(pipe_calls == initial_creates + 1 && pipe_query_calls == 1 && pipe_growth_calls == 1,
            "pool reuse recreated the pipe or retried growth before its cooldown");

    pipe_time_us = initial.capacity_retry_at_us;
    require(sbufSpliceInitPipe(buf, preferred) == 0 && pipe_query_calls == 2 && pipe_growth_calls == 2 &&
                sbufSpliceMetadata(buf).capacity_retry_at_us == pipe_time_us + 1000000,
            "persistent growth failure did not start another cooldown");

    // Expiring the cooldown while payload is held must not resize or consume it.
    require(write(initial.pipefd[1], "x", 1) == 1, "could not fill the undersized pipe");
    buf->len      = 1;
    buf->capacity = buf->l_pad + 1;
    pipe_time_us += 1000000;
    pipe_growth_error = 0;
    require(sbufSpliceInitPipe(buf, preferred) == 0 && pipe_query_calls == 2 && pipe_growth_calls == 2,
            "initialization retried growth on a nonempty buffer");
    sbuf_t *dest = bufferpoolGetSmallBuffer(env.buffers);
    sbufSpliceReadToBuffer(buf, dest, 1);
    require(sbufGetLength(dest) == 1 && memoryEqual(sbufGetRawPtr(dest), "x", 1),
            "growth retry disturbed the pipe payload");
    bufferpoolReuseBuffer(env.buffers, dest);
    bufferpoolReuseBuffer(env.buffers, buf);
    buf = bufferpoolGetSpliceBuffer(env.buffers);
    require(buf != NULL && pipe_query_calls == 3 && pipe_growth_calls == 3,
            "empty pooled pipe did not retry after pressure cleared");
    splice_buffer_metadata_t metadata = sbufSpliceMetadata(buf);
    require(metadata.pipe_capacity == preferred && metadata.capacity_retry_at_us == 0 &&
                metadata.pipefd[0] == initial.pipefd[0] && metadata.pipefd[1] == initial.pipefd[1],
            "successful retry replaced the pair or failed to clear retry state");
    pipe_time_us += 10000000;
    const unsigned int clock_calls = pipe_time_calls;
    require(sbufSpliceInitPipe(buf, preferred) == 0 && sbufSpliceInitPipe(buf, 4096) == 0 && pipe_query_calls == 3 &&
                pipe_growth_calls == 3 && pipe_time_calls == clock_calls,
            "adequate-capacity reuse queried the clock, renegotiated, or shrank the pipe");

    sbufSpliceClosePipe(buf);
    metadata = sbufSpliceMetadata(buf);
    require(metadata.pipefd[0] == -1 && metadata.pipefd[1] == -1 && metadata.pipe_capacity == 0 &&
                metadata.capacity_retry_at_us == 0,
            "pipe close retained stale capacity or retry state");
    pipe_capacity    = 65536;
    pipe_query_error = EINVAL;
    require(sbufSpliceInitPipe(buf, preferred) == 0 && pipe_query_calls == 4 && pipe_growth_calls == 3 &&
                sbufSpliceMetadata(buf).pipe_capacity == 0,
            "query failure did not preserve the new usable pipe with unknown capacity");
    require(sbufSpliceInitPipe(buf, preferred) == 0 && pipe_query_calls == 4,
            "unknown capacity bypassed its retry cooldown");
    pipe_time_us += 1000000;
    pipe_query_error = 0;
    require(sbufSpliceInitPipe(buf, preferred) == 0 && pipe_query_calls == 5 && pipe_growth_calls == 4 &&
                sbufSpliceMetadata(buf).pipe_capacity == preferred,
            "unknown-capacity pipe failed to recover after a query failure");
    bufferpoolReuseBuffer(env.buffers, buf);
    mock_pipe_capacity = mock_pipe_time = false;
    teardown(&env);
}

typedef enum splice_case_e
{
    kSpliceConvertPipe,
    kSplicePartialPipe,
    kSpliceRetainPipe,
    kSpliceRetainPartial,
    kSpliceCloseBeforeRecycle,
    kSpliceCloseAfterRecycle,
    kSpliceForwardWrite,
    kSpliceDisabled,
    kSplicePipeFallback,
    kSpliceDroppedPayload,
    kSpliceDirectRecycleEmpty,
    kSpliceRecycleUnused,
    kSpliceSmallDestination,
    kSplicePartialRange,
    kSplicePartialCapacity,
    kSpliceResidualPipe,
    kSpliceShortPipe,
    kSpliceShortPartial,
    kSpliceEOFPipe,
    kSpliceEOFPartial,
    kSpliceFailedRead,
    kSpliceFailedPartial,
    kSpliceInvalidFlags,
    kSpliceWriteRawIP,
    kSpliceWriteError,
    kSpliceWriteCloseQueue,
    kSpliceWriteClosed
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
    wio_t        *destination;
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
    if (probe->kind == kSpliceDisabled || (probe->kind == kSplicePipeFallback && probe->calls == 1))
    {
        require(buf->flags == 0 && count <= bufferpoolGetLargeBufferSize(pool) &&
                    count <= probe->length - probe->received &&
                    memoryEqual(sbufGetRawPtr(buf), probe->data + probe->received, count),
                "ordinary read did not deliver the expected bytes");
        probe->received += count;
        bufferpoolReuseBuffer(pool, buf);
        return;
    }

    const uint32_t limit = bufferpoolGetSplicePayloadLimit(pool);
    require(count <= min(probe->length - probe->received, limit) && count > 0,
            "splice delivery exceeded available bytes or its read cap");
    require(buf->flags == kSbufFlagSplice && buf->curpos == 64 && buf->capacity == 64 + count,
            "splice dispatch supplied an invalid pipe-backed wrapper");
    const splice_buffer_metadata_t metadata  = sbufSpliceMetadata(buf);
    int                            available = -1;
    require(ioctl(metadata.pipefd[0], FIONREAD, &available) == 0 && available == (int) count,
            "delivered length did not match actual private-pipe bytes");
    const int source_fd = wioGetFD(io);

    switch (probe->kind)
    {
    case kSpliceDroppedPayload: {
        sbufShiftLeft(buf, 4);
        sbufWrite(buf, "HEAD", 4);
        bufferpoolReuseBuffer(pool, buf);
        sbuf_t *reused = bufferpoolGetSpliceBuffer(pool);
        require(reused == buf && sbufSpliceIsReusable(reused) &&
                    sbufSpliceMetadata(reused).pipefd[0] == metadata.pipefd[0] &&
                    sbufSpliceMetadata(reused).pipefd[1] == metadata.pipefd[1],
                "direct pool return did not discard and retain its private pipe");
        bufferpoolReuseBuffer(pool, reused);
        probe->received += count;
        return;
    }
    case kSpliceDirectRecycleEmpty: {
        sbuf_t *dest = bufferpoolGetLargeBuffer(pool);
        sbufSpliceReadToBuffer(buf, dest, count);
        bufferpoolReuseBuffer(pool, dest);
        bufferpoolReuseBuffer(pool, buf);
        probe->received += count;
        return;
    }
    case kSpliceRecycleUnused:
        bufferpoolReuseBuffer(pool, bufferpoolGetSpliceBuffer(pool));
        bufferpoolReuseBuffer(pool, sbufSpliceMaterializeToBuffer(buf, bufferpoolGetLargeBuffer(pool), pool));
        probe->received += count;
        return;
    case kSpliceSmallDestination:
        sbufSpliceMaterializeToBuffer(buf, sbufCreateWithPadding(0, 64), pool);
        break;
    case kSplicePartialRange:
        sbufSpliceReadToBuffer(buf, bufferpoolGetLargeBuffer(pool), count + 1);
        break;
    case kSplicePartialCapacity: {
        sbuf_t *dest = bufferpoolGetLargeBuffer(pool);
        sbufSetLength(dest, sbufGetMaximumWriteableSize(dest));
        sbufSpliceReadToBuffer(buf, dest, 1);
        break;
    }
    case kSpliceResidualPipe:
        buf->len = 0;
        bufferpoolReuseBuffer(pool, buf);
        break;
    case kSpliceShortPipe:
    case kSpliceShortPartial:
    case kSpliceEOFPipe:
    case kSpliceEOFPartial:
        if (probe->kind == kSpliceEOFPipe || probe->kind == kSpliceEOFPartial)
        {
            splice_buffer_metadata_t closed_writer = metadata;
            require(close(closed_writer.pipefd[1]) == 0, "failed to close pipe writer for EOF fixture");
            closed_writer.pipefd[1] = -1;
            sbufSpliceSetMetadata(buf, closed_writer);
        }
        ++buf->capacity;
        sbufSetLength(buf, count + 1);
        if (probe->kind == kSpliceShortPartial || probe->kind == kSpliceEOFPartial)
            sbufSpliceReadToBuffer(buf, bufferpoolGetLargeBuffer(pool), count + 1);
        else
            sbufSpliceMaterializeToBuffer(buf, bufferpoolGetLargeBuffer(pool), pool);
        break;
    case kSpliceFailedRead:
        pipe_read_fd    = metadata.pipefd[0];
        pipe_read_error = EAGAIN;
        sbufSpliceMaterializeToBuffer(buf, bufferpoolGetLargeBuffer(pool), pool);
        break;
    case kSpliceFailedPartial:
        pipe_read_fd          = metadata.pipefd[0];
        pipe_read_error       = EIO;
        pipe_read_limit       = 2;
        pipe_read_calls       = 0;
        pipe_read_error_after = 1;
        sbufSpliceReadToBuffer(buf, bufferpoolGetLargeBuffer(pool), count);
        break;
    case kSpliceInvalidFlags:
        buf->flags &= (uint16_t) ~kSbufFlagSplice;
        sbufSpliceReadToBuffer(buf, bufferpoolGetLargeBuffer(pool), 1);
        break;
    case kSpliceWriteRawIP:
        io->io_type = WIO_TYPE_IP;
        wioWrite(io, buf);
        break;
    case kSpliceWriteError:
        sbufShiftLeft(buf, 4);
        sbufWrite(buf, "HEAD", 4);
        write_test_fd = source_fd;
        splice_error  = EPIPE;
        wioWrite(io, buf);
        probe->received += count;
        return;
    case kSpliceWriteCloseQueue:
        write_test_fd = source_fd;
        splice_error  = EAGAIN;
        require(wioWrite(io, buf) == 0, "failed to queue splice close fixture");
        wioFree(io);
        probe->received += count;
        return;
    case kSpliceWriteClosed:
        wioClose(io);
        wioWrite(io, buf);
        probe->received += count;
        return;
    default:
        break;
    }
    require(probe->kind <= kSplicePipeFallback, "a splice failure case returned instead of aborting");
    sbufShiftLeft(buf, 4);
    sbufWrite(buf, "HEAD", 4);
    if (probe->kind == kSpliceRetainPipe || probe->kind == kSpliceRetainPartial)
    {
        if (probe->kind == kSpliceRetainPartial)
        {
            sbuf_t *dest = bufferpoolGetLargeBuffer(pool);
            sbufSpliceReadToBuffer(buf, dest, 6);
            require(sbufGetLength(dest) == 6 && memoryEqual(sbufGetRawPtr(dest), "HEAD", 4),
                    "deferred partial read lost its prefix");
            bufferpoolReuseBuffer(pool, dest);
        }
        probe->held = buf;
        probe->received += count;
        wioFree(io);
        requireClosed(source_fd);
        return;
    }
    if (probe->kind == kSpliceForwardWrite)
    {
        require(wioWrite(probe->destination, buf) == (int) count + 4, "forwarded pipe-backed write did not complete");
        probe->received += count;
        return;
    }

    const bool partial = probe->kind == kSplicePartialPipe;
    sbuf_t    *dest    = bufferpoolGetBestFit(pool, count + 6, 64);
    if (probe->kind == kSpliceCloseBeforeRecycle)
    {
        wioFree(io);
        requireClosed(source_fd);
    }
    if (partial)
    {
        sbufSetLength(dest, 2);
        sbufWrite(dest, ">>", 2);
        require(sbufSpliceReadToBuffer(buf, dest, 0) == dest && sbufGetLength(dest) == 2 &&
                    sbufGetLength(buf) == count + 4,
                "zero-byte partial read changed either buffer");
        sbufSpliceReadToBuffer(buf, dest, 2);
        require(buf->curpos == 62, "prefix-only read advanced beyond the real prefix");
        sbufSpliceReadToBuffer(buf, dest, 4);
        require(buf->curpos == 64 && buf->capacity == 64 + count - 2 && sbufGetLength(buf) == count - 2,
                "mixed prefix/body read left incorrect source accounting");
        sbufSpliceReadToBuffer(buf, dest, sbufGetLength(buf));
        require(sbufGetLength(buf) == 0 && buf->curpos == 64 && buf->capacity == 64,
                "full partial consumption did not leave an empty wrapper");
        bufferpoolReuseBuffer(pool, buf);
    }
    else
    {
        require(sbufSpliceMaterializeToBuffer(buf, dest, pool) == dest,
                "full conversion did not return caller-supplied storage");
    }
    requireSplicePayload(probe, dest, count, partial);
    probe->received += count;
    bufferpoolReuseBuffer(pool, dest);
    if (probe->kind == kSpliceCloseAfterRecycle)
    {
        wioFree(io);
        requireClosed(source_fd);
    }
}

static void runSpliceCase(splice_case_t kind, uint32_t large_size, uint32_t length)
{
    test_env_t env;
    setupWithBufferSize(&env, large_size);
    bufferpoolUpdateAllocationPaddings(env.buffers, 64, 64, 64, 64);
    int            sockets[2];
    wio_t         *io    = socketIO(&env, sockets);
    splice_probe_t probe = {.env = &env, .kind = kind, .length = length};
    int            destination_fds[2];
    if (kind == kSpliceForwardWrite)
    {
        probe.destination = socketIO(&env, destination_fds);
    }
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
    read_test_fd = sockets[0];
    // No data and no EOF: splice and its ordinary fallback must both defer delivery.
    const int deferred_read_error = splice_read_error;
    splice_read_error             = 0;
    io->revents = WW_READ;
    EVENT_PENDING(io);
    require(wloopProcessEvents(env.loop, 0) >= 0 && probe.calls == 0 && ! io->closed,
            "spurious readiness fabricated payload or closed a live socket");
    splice_read_error = deferred_read_error;
    // Deliveries can exceed the kernel send buffer; feed without blocking the reader's own thread.
    uint32_t supplied = 0;
    for (unsigned int attempt = 0; attempt < 256 && probe.received < length; ++attempt)
    {
        if (supplied < length)
        {
            const ssize_t sent = send(sockets[1], probe.data + supplied, length - supplied, MSG_DONTWAIT);
            if (sent > 0)
                supplied += (uint32_t) sent;
            else
                require(sent < 0 && (errno == EAGAIN || errno == EINTR), "failed to queue splice fixture bytes");
        }
        require(wloopProcessEvents(env.loop, 0) >= 0, "splice fixture dispatch failed");
    }
    if (kind == kSpliceWriteError)
        wloopProcessEvents(env.loop, 0);
    require(probe.received == length, "splice dispatch did not consume all queued bytes");
    if (kind == kSpliceRetainPipe || kind == kSpliceRetainPartial)
    {
        require(probe.closes == 1 && probe.held != NULL, "private pipe did not outlive WIO close");
        const int reader = sbufSpliceMetadata(probe.held).pipefd[0], writer = sbufSpliceMetadata(probe.held).pipefd[1];
        sbuf_t *dest = bufferpoolGetLargeBuffer(env.buffers);
        sbufSpliceMaterializeToBuffer(probe.held, dest, env.buffers);
        probe.received = 0;
        if (kind == kSpliceRetainPartial)
            require(sbufGetLength(dest) == length - 2 && memoryEqual(sbufGetRawPtr(dest), probe.data + 2, length - 2),
                    "deferred partial buffer lost remaining pipe bytes");
        else
            requireSplicePayload(&probe, dest, length, false);
        bufferpoolReuseBuffer(env.buffers, dest);
        requireClosed(sockets[0]);
        require(fcntl(reader, F_GETFD) >= 0 && fcntl(writer, F_GETFD) >= 0, "recycled private pipe was closed");
        close(sockets[1]);
    }
    else if (kind == kSpliceCloseBeforeRecycle || kind == kSpliceCloseAfterRecycle || kind == kSpliceWriteError ||
             kind == kSpliceWriteCloseQueue || kind == kSpliceWriteClosed)
    {
        require(probe.closes == 1, "recycling/cancellation callback did not close its WIO");
        requireClosed(sockets[0]);
        close(sockets[1]);
    }
    else
    {
        close(sockets[1]);
        require(wloopProcessEvents(env.loop, 0) >= 0 && probe.closes == 1 && wioIsClosed(io),
                "ordinary EOF confirmation failed to close the connection");
    }
    if (kind == kSpliceForwardWrite)
    {
        uint8_t received[64];
        require(length + 4 <= sizeof(received) &&
                    recv(destination_fds[1], received, sizeof(received), MSG_DONTWAIT) == (ssize_t) length + 4 &&
                    memoryEqual(received, "HEAD", 4) && memoryEqual(received + 4, probe.data, length),
                "forwarded splice read did not reach the destination intact");
        wioClose(probe.destination);
        close(destination_fds[1]);
    }
    write_test_fd = read_test_fd = -1;
    send_error = splice_error = 0;
    teardown(&env);
}

static void testSpliceReadCapacityPreference(void)
{
    for (unsigned int mode = 0; mode < 3; ++mode)
    {
        const uint32_t read_limit = SPLICE_PAYLOAD_LIMIT;
        mock_pipe_capacity        = true;
        pipe_capacity             = 65536;
        pipe_query_error          = 0;
        pipe_growth_error         = mode == 1 ? EPERM : 0;
        pipe_query_calls = pipe_growth_calls = 0;
        pipe_requested_capacity              = 0;
        runSpliceCase(kSpliceConvertPipe, mode == 0 ? LARGE_BUFFER_SIZE_RAM_LOW : LARGE_BUFFER_SIZE_RAM_HIGH, 9);
        require(splice_read_requested == read_limit, "NIO did not request the independent splice limit");
        require(pipe_query_calls == 1 && pipe_growth_calls == 1,
                "read loop negotiated the wrong pipe capacity for its buffer profile");
        require(pipe_requested_capacity == (int) read_limit,
                "read loop sized the pipe to current availability instead of its read limit");
    }
    mock_pipe_capacity = false;
    pipe_growth_error  = 0;
}

static void testSplicePipeFallback(void)
{
    test_env_t env;
    setup(&env);
    bufferpoolUpdateAllocationPaddings(env.buffers, 64, 64, 64, 64);
    int            sockets[2];
    wio_t         *io    = socketIO(&env, sockets);
    splice_probe_t probe = {.env = &env, .kind = kSplicePipeFallback, .length = 9};
    memcpy(probe.data, "123456789", 9);
    weventSetUserData(io, &probe);
    wioSetCallBackRead(io, spliceRead);
    require(wioEnableSplice(io) == 0 && wioRead(io) == 0, "failed to start pipe-fallback reads");
    sbuf_t *unused = bufferpoolGetSpliceBuffer(env.buffers);
    require(unused != NULL, "failed to prepare fallback wrapper");
    sbufSpliceClosePipe(unused);
    bufferpoolReuseBuffer(env.buffers, unused);
    read_test_fd                    = sockets[0];
    splice_read_calls               = 0;
    const unsigned int pipes_before = pipe_calls;
    fail_pipe                       = true;
    require(send(sockets[1], probe.data, 9, 0) == 9, "failed to supply pipe-fallback payload");
    require(wloopProcessEvents(env.loop, 0) >= 0 && probe.calls == 1 && probe.received == 9,
            "pipe creation failure did not deliver ordinary bytes");
    require(! fail_pipe && pipe_calls == pipes_before + 1 && splice_read_calls == 0 && wioIsSpliceEnabled(io) &&
                ! wioIsClosed(io) && wioGetError(io) == 0,
            "pipe creation failure attempted splice or changed source state");
    sbuf_t *reused = bufferpoolGetSpliceBuffer(env.buffers);
    require(reused == unused && sbufSpliceIsReusable(reused) && sbufSpliceMetadata(reused).pipefd[0] >= 0 &&
                sbufSpliceMetadata(reused).pipefd[1] >= 0 && pipe_calls == pipes_before + 2,
            "pipe creation failure leaked or damaged the unused wrapper");
    bufferpoolReuseBuffer(env.buffers, reused);

    probe.received = 0;
    require(send(sockets[1], probe.data, 9, 0) == 9, "failed to supply subsequent splice payload");
    require(wloopProcessEvents(env.loop, 0) >= 0 && probe.calls == 2 && probe.received == 9 &&
                pipe_calls == pipes_before + 2 && splice_read_calls == 1,
            "later delivery did not resume splice after pipe creation recovered");
    wioClose(io);
    close(sockets[1]);
    read_test_fd = -1;
    teardown(&env);
}

static void testSpliceReadConditions(void)
{
    for (unsigned int mode = 0; mode < 3; ++mode)
    {
        splice_read_calls = 0;
        splice_read_error = mode == 0 ? EAGAIN : mode == 1 ? EINTR : 0;
        splice_read_limit = mode == 2 ? 4 : SIZE_MAX;
        runSpliceCase(mode == 0 ? kSplicePipeFallback : kSpliceConvertPipe, 4096, 9);
        require(splice_read_error == 0 && splice_read_calls == mode + 3,
                "read loop did not retry transient input or deliver actual short-splice lengths");
        splice_read_limit = SIZE_MAX;
    }
    // Zero splice progress with queued data, errors, admission closure after splice,
    // and a missing callback must settle every still-local wrapper.
    for (unsigned int mode = 0; mode < 4; ++mode)
    {
        test_env_t env;
        setup(&env);
        bufferpoolUpdateAllocationPaddings(env.buffers, 64, 64, 64, 64);
        int            sockets[2];
        wio_t         *io    = socketIO(&env, sockets);
        splice_probe_t probe = {.env = &env, .kind = mode == 0 ? kSplicePipeFallback : kSpliceConvertPipe, .length = 9};
        memcpy(probe.data, "123456789", 9);
        weventSetUserData(io, &probe);
        wioSetCallBackClose(io, spliceClosed);
        wioSetCallBackRead(io, mode == 3 ? NULL : spliceRead);
        require(wioEnableSplice(io) == 0 && wioRead(io) == 0, "failed to initialize read-condition fixture");
        read_test_fd              = sockets[0];
        splice_read_eof           = mode == 0;
        splice_read_error         = mode == 1 ? ECONNRESET : 0;
        quiesce_after_splice_read = mode == 2 ? env.loop : NULL;
        require(send(sockets[1], probe.data, 9, 0) == 9, "failed to supply read-condition payload");
        require(wloopProcessEvents(env.loop, 0) >= 0 && probe.calls == (mode == 0 ? 1U : 0U),
                "read loop delivered payload after a terminal or suppressed read");
        if (mode == 1)
        {
            require(probe.closes == 1 && wioIsClosed(io) && wioGetError(io) == (mode == 1 ? ECONNRESET : 0),
                    "splice EOF/error did not follow normal read closure");
        }
        else
        {
            require(! wioIsClosed(io) && quiesce_after_splice_read == NULL,
                    "suppressed delivery closed its source or missed the quiescence hook");
            if (mode == 0)
                require(probe.received == 9, "zero splice progress discarded readable ordinary bytes");
        }
        sbuf_t *reused = bufferpoolGetSpliceBuffer(env.buffers);
        require(sbufSpliceMetadata(reused).pipefd[1] == last_splice_read_pipe && sbufSpliceIsReusable(reused),
                "undelivered read leaked its wrapper or retained private-pipe bytes");
        bufferpoolReuseBuffer(env.buffers, reused);
        wioClose(io);
        close(sockets[1]);
        read_test_fd = -1;
        teardown(&env);
    }
}

static void testDirectSpliceRead(void)
{
    test_env_t env;
    setup(&env);
    bufferpoolUpdateAllocationPaddings(env.buffers, 64, 64, 64, 64);
    int            sockets[2];
    wio_t         *io    = socketIO(&env, sockets);
    splice_probe_t probe = {.env = &env, .kind = kSpliceConvertPipe, .length = 9};
    memcpy(probe.data, "123456789", 9);
    weventSetUserData(io, &probe);
    wioSetCallBackRead(io, spliceRead);
    require(wioEnableSplice(io) == 0 && wioRead(io) == 0, "failed to start direct splice read");
    read_test_fd        = sockets[0];
    socket_read_queries = splice_read_calls = 0;
    require(send(sockets[1], probe.data, 9, 0) == 9, "failed to supply direct splice bytes");
    require(wloopProcessEvents(env.loop, 0) >= 0 && probe.received == 9 && probe.calls == 1 && splice_read_calls == 1 &&
                splice_read_requested == 4096 && socket_read_queries == 0,
            "direct splice queried socket availability or required the full requested count");
    wioClose(io);
    close(sockets[1]);
    read_test_fd = -1;
    teardown(&env);
}

typedef struct urgent_read_probe_s
{
    buffer_pool_t *pool;
    uint8_t        data[16];
    uint32_t       received;
    unsigned int   splice_calls;
    unsigned int   ordinary_calls;
} urgent_read_probe_t;

static void urgentRead(wio_t *io, sbuf_t *buf)
{
    urgent_read_probe_t *probe = weventGetUserdata(io);
    if (buf->flags & kSbufFlagSplice)
    {
        ++probe->splice_calls;
        buf = sbufSpliceMaterializeToBuffer(buf, bufferpoolGetLargeBuffer(probe->pool), probe->pool);
    }
    else
    {
        ++probe->ordinary_calls;
    }
    require(sbufGetLength(buf) <= sizeof(probe->data) - probe->received, "urgent fixture received excess data");
    memcpy(probe->data + probe->received, sbufGetRawPtr(buf), sbufGetLength(buf));
    probe->received += sbufGetLength(buf);
    bufferpoolReuseBuffer(probe->pool, buf);
}

static void testSpliceUrgentRead(void)
{
    for (unsigned int mode = 0; mode < 4; ++mode)
    {
        test_env_t env;
        setup(&env);
        int listener = socket(AF_INET, SOCK_STREAM, 0);
        require(listener >= 0, "failed to create urgent fixture listener");
        struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        require(bind(listener, (struct sockaddr *) &address, sizeof(address)) == 0 && listen(listener, 1) == 0,
                "failed to bind urgent fixture listener");
        socklen_t size = sizeof(address);
        require(getsockname(listener, (struct sockaddr *) &address, &size) == 0, "failed to get urgent fixture port");
        int sender = socket(AF_INET, SOCK_STREAM, 0);
        require(sender >= 0 && connect(sender, (struct sockaddr *) &address, sizeof(address)) == 0,
                "failed to connect urgent fixture sender");
        int receiver = accept(listener, NULL, NULL);
        require(receiver >= 0, "failed to accept urgent fixture connection");
        close(listener);
        const int inline_urgent = mode & 1U;
        const int nodelay       = 1;
        require(setsockopt(receiver, SOL_SOCKET, SO_OOBINLINE, &inline_urgent, sizeof(inline_urgent)) == 0 &&
                    setsockopt(sender, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay)) == 0,
                "failed to configure urgent fixture sockets");
        wio_t              *io    = wioGet(env.loop, receiver);
        urgent_read_probe_t probe = {.pool = env.buffers};
        weventSetUserData(io, &probe);
        wioSetCallBackRead(io, urgentRead);
        require(wioEnableSplice(io) == 0 && wioRead(io) == 0, "failed to start urgent fixture reads");
        require(send(sender, "AAA", 3, 0) == 3 && send(sender, "!", 1, MSG_OOB) == 1 && send(sender, "BBB", 3, 0) == 3,
                "failed to supply urgent fixture payload");
        const bool half_closed = mode >= 2;
        if (half_closed)
            require(shutdown(sender, SHUT_WR) == 0, "failed to half-close urgent fixture sender");
        const uint32_t expected = inline_urgent ? 7 : 6;
        for (unsigned int attempt = 0;
             attempt < 32 && (probe.received < expected || (half_closed && ! wioIsClosed(io)));
             ++attempt)
            require(wloopProcessEvents(env.loop, 10) >= 0, "urgent fixture dispatch failed");
        require(probe.received == expected && memoryEqual(probe.data, inline_urgent ? "AAA!BBB" : "AAABBB", expected) &&
                    probe.splice_calls > 0 && probe.ordinary_calls > 0,
                "splice stalled or lost bytes at an urgent boundary");
        if (half_closed)
        {
            require(wioIsClosed(io), "urgent EOF did not close after all ordinary bytes were delivered");
        }
        else
        {
            const unsigned int previous_splices = probe.splice_calls;
            require(! wioIsClosed(io) && wioIsSpliceEnabled(io) && send(sender, "CCC", 3, 0) == 3,
                    "ordinary fallback disabled splice or closed the source");
            for (unsigned int attempt = 0; attempt < 32 && probe.received < expected + 3; ++attempt)
                require(wloopProcessEvents(env.loop, 10) >= 0, "post-urgent dispatch failed");
            require(probe.received == expected + 3 && memoryEqual(probe.data + expected, "CCC", 3) &&
                        probe.splice_calls > previous_splices,
                    "reads did not resume splice after the urgent boundary");
            wioClose(io);
        }
        close(sender);
        teardown(&env);
    }
}

typedef struct deferred_reads_s
{
    sbuf_t      *buffers[2];
    unsigned int count;
} deferred_reads_t;

static void deferSpliceRead(wio_t *io, sbuf_t *buf)
{
    deferred_reads_t *held = weventGetUserdata(io);
    require(held->count < 2 && sbufGetLength(buf) == 3 && buf->flags == kSbufFlagSplice,
            "invalid deferred read wrapper");
    held->buffers[held->count++] = buf;
    if (held->count == 2)
    {
        const int fd = wioGetFD(io);
        wioFree(io);
        requireClosed(fd);
    }
}

static void testDeferredSpliceReads(void)
{
    test_env_t env;
    setup(&env);
    int              sockets[2];
    wio_t           *io   = socketIO(&env, sockets);
    deferred_reads_t held = {0};
    weventSetUserData(io, &held);
    wioSetCallBackRead(io, deferSpliceRead);
    require(wioEnableSplice(io) == 0 && wioRead(io) == 0, "failed to start deferred splice reads");
    read_test_fd      = sockets[0];
    splice_read_limit = 3;
    require(send(sockets[1], "AAABBB", 6, 0) == 6, "failed to supply independent read bodies");
    for (unsigned int attempt = 0; attempt < 4 && held.count < 2; ++attempt)
        require(wloopProcessEvents(env.loop, 0) >= 0, "deferred read dispatch failed");
    require(held.count == 2 &&
                sbufSpliceMetadata(held.buffers[0]).pipefd[0] != sbufSpliceMetadata(held.buffers[1]).pipefd[0],
            "unconsumed callback prevented a later independent read");
    sbuf_t *dest = bufferpoolGetLargeBuffer(env.buffers);
    sbufSpliceMaterializeToBuffer(held.buffers[1], dest, env.buffers);
    require(sbufGetLength(dest) == 3 && memoryEqual(sbufGetRawPtr(dest), "BBB", 3), "B consumed A's bytes");
    sbufSpliceMaterializeToBuffer(held.buffers[0], dest, env.buffers);
    require(sbufGetLength(dest) == 3 && memoryEqual(sbufGetRawPtr(dest), "AAA", 3), "deferred A lost its bytes");
    bufferpoolReuseBuffer(env.buffers, dest);
    close(sockets[1]);
    read_test_fd      = -1;
    splice_read_limit = SIZE_MAX;
    teardown(&env);
}

static sbuf_t *makeSpliceWriteBuffer(test_env_t *env, wio_t *source, int peer, const char *body, const char *prefix)
{
    const uint32_t body_bytes = (uint32_t) strlen(body), prefix_bytes = (uint32_t) strlen(prefix);
    sbuf_t        *buf = bufferpoolGetSpliceBuffer(env->buffers);
    require(buf != NULL, "failed to check out write fixture pipe");
    if (body_bytes != 0)
    {
        require(send(peer, body, body_bytes, 0) == (ssize_t) body_bytes, "failed to supply splice write body");
        require(__real_splice(
                    wioGetFD(source), NULL, sbufSpliceMetadata(buf).pipefd[1], NULL, body_bytes, SPLICE_F_NONBLOCK) ==
                    (ssize_t) body_bytes,
                "failed to fill write fixture pipe");
    }
    buf->capacity = (uint32_t) sbufGetLeftPadding(buf) + body_bytes;
    sbufSetLength(buf, body_bytes);
    sbufShiftLeft(buf, prefix_bytes);
    sbufWrite(buf, prefix, prefix_bytes);
    return buf;
}

static void testSpliceBufferQueue(void)
{
    test_env_t env;
    setup(&env);
    bufferpoolUpdateAllocationPaddings(env.buffers, 64, 64, 64, 64);
    int            sockets[2];
    wio_t         *source   = socketIO(&env, sockets);
    buffer_queue_t queue    = bufferqueueCreate(1);
    sbuf_t        *a        = makeSpliceWriteBuffer(&env, source, sockets[1], "AAA", "a:");
    sbuf_t        *b        = makeSpliceWriteBuffer(&env, source, sockets[1], "BBB", "b:");
    sbuf_t        *empty    = bufferpoolGetSpliceBuffer(env.buffers);
    sbuf_t        *ordinary = bufferpoolGetSmallBuffer(env.buffers);
    sbufSetLength(ordinary, 6);
    sbufWrite(ordinary, "NORMAL", 6);
    ordinary = bufferqueuePushBack(&queue, ordinary);
    require(bufferqueuePushFront(&queue, a) == a && bufferqueuePushBack(&queue, empty) == empty &&
                bufferqueueTryPushBack(&queue, &b),
            "mixed queue insertion failed or replaced a splice wrapper");
    require(bufferqueueGetBufCount(&queue) == 4 && bufferqueueGetBufLen(&queue) == 16 && bufferqueueFront(&queue) == a,
            "mixed queue lost entries, order, or logical byte accounting");
    size_t charge =
        sbufGetQueueCharge(a) + sbufGetQueueCharge(ordinary) + sbufGetQueueCharge(empty) + sbufGetQueueCharge(b);
    require(bufferqueueGetCharge(&queue) == charge, "mixed queue omitted ordinary, empty or splice charge");

    buffer_budget_t budget;
    bufferbudgetInit(&budget, (buffer_budget_cost_t) {16, charge, 4});
    require(bufferqueueTryAttachBudget(&queue, &budget) && budget.used.charge == charge && budget.used.entries == 4,
            "populated mixed queue exact attachment failed");
    buffer_budget_reservation_t active = {0};
    charge -= sbufGetQueueCharge(a);
    require(bufferqueuePopFrontReserved(&queue, &active) == a && bufferqueueGetBufLen(&queue) == 11,
            "splice pop changed identity or queue accounting");
    require(bufferqueueGetCharge(&queue) == charge, "popped splice allocation remained charged to queue");
    sbuf_t *dest = bufferpoolGetLargeBuffer(env.buffers);
    sbufSpliceReadToBuffer(a, dest, 3);
    require(sbufGetLength(dest) == 3 && memoryEqual(sbufGetRawPtr(dest), "a:A", 3),
            "queued splice lost its real prefix or body");
    require(budget.used.bytes == 16 && budget.used.entries == 4, "mixed active retention disappeared");
    buffer_budget_cost_t remainder_cost;
    require(bufferbudgetTryGetCost(a, &remainder_cost), "splice remainder cost");
    bufferbudgetReservationReduce(&active, remainder_cost);
    sbuf_t *remainder = a;
    require(bufferqueueTryPushFrontReserved(&queue, &remainder, &active) && remainder == a &&
                bufferqueueGetBufLen(&queue) == 13 && bufferqueueGetBufCount(&queue) == 4,
            "partial splice reinsertion changed ownership or byte accounting");
    charge += sbufGetQueueCharge(a);
    require(bufferqueueGetCharge(&queue) == charge, "splice reinsertion used its old capacity charge");
    require(active.budget == NULL && budget.used.bytes == 13 && budget.used.charge == charge,
            "splice reservation reconciliation or reinsertion double charged");
    wioClose(source);
    requireClosed(sockets[0]);
    close(sockets[1]);

    sbufSpliceMaterializeToBuffer(bufferqueuePopFront(&queue), dest, env.buffers);
    require(sbufGetLength(dest) == 2 && memoryEqual(sbufGetRawPtr(dest), "AA", 2),
            "queued remainder depended on the source or read another pipe's bytes");
    require(bufferqueuePopFront(&queue) == ordinary && ordinary->flags == 0 && sbufGetLength(ordinary) == 6 &&
                memoryEqual(sbufGetRawPtr(ordinary), "NORMAL", 6),
            "mixed queue changed ordinary payload or entry order");
    bufferpoolReuseBuffer(env.buffers, ordinary);
    require(bufferqueuePopFront(&queue) == empty, "zero-length splice entry was dropped");
    bufferpoolReuseBuffer(env.buffers, empty);
    require(bufferqueuePopFront(&queue) == b, "queue replaced the second private body");
    sbufSpliceMaterializeToBuffer(b, dest, env.buffers);
    require(sbufGetLength(dest) == 5 && memoryEqual(sbufGetRawPtr(dest), "b:BBB", 5),
            "queue mixed independent private bodies");
    bufferpoolReuseBuffer(env.buffers, dest);
    require(bufferqueueGetBufCount(&queue) == 0 && bufferqueueGetBufLen(&queue) == 0 &&
                bufferqueueGetCharge(&queue) == 0 && bufferqueueFront(&queue) == NULL &&
                bufferqueuePopFront(&queue) == NULL,
            "drained mixed queue retained entries or bytes");
    bufferbudgetAssertEmpty(&budget);
    testWorkerUnbindWID();
    bufferqueueDestroy(&queue);
    testWorkerBindWID(0);
    teardown(&env);
}

static void testSpliceQueueCleanupAndRefusal(void)
{
    test_env_t env;
    setup(&env);
    bufferpoolUpdateAllocationPaddings(env.buffers, 64, 64, 64, 64);
    int    sockets[2];
    wio_t *source = socketIO(&env, sockets);
    for (unsigned int mode = 0; mode < 3; ++mode)
    {
        buffer_queue_t queue    = bufferqueueCreate(1);
        sbuf_t        *ordinary = bufferpoolGetSmallBuffer(env.buffers);
        sbufSetLength(ordinary, 1);
        sbufWrite(ordinary, "X", 1);
        ordinary                                = bufferqueuePushBack(&queue, ordinary);
        sbuf_t                        *buf      = makeSpliceWriteBuffer(&env, source, sockets[1], "OLD", "prefix:");
        const splice_buffer_metadata_t metadata = sbufSpliceMetadata(buf);
        const uint32_t                 length = buf->len, cursor = buf->curpos, capacity = buf->capacity;
        if (mode == 0)
        {
            // Refused growth in either direction must leave ownership and the private body untouched.
            for (unsigned int front = 0; front < 2; ++front)
            {
                sbuf_t *input         = buf;
                fail_queue_allocation = true;
                const bool accepted =
                    front ? bufferqueueTryPushFront(&queue, &input) : bufferqueueTryPushBack(&queue, &input);
                int available = -1;
                require(! accepted && ! fail_queue_allocation && input == buf && buf->len == length &&
                            buf->curpos == cursor && buf->capacity == capacity &&
                            sbufSpliceMetadata(buf).pipefd[0] == metadata.pipefd[0] &&
                            sbufSpliceMetadata(buf).pipefd[1] == metadata.pipefd[1] &&
                            ioctl(metadata.pipefd[0], FIONREAD, &available) == 0 && available == 3 &&
                            memoryEqual(sbufGetRawPtr(buf), "prefix:", 7) && bufferqueueGetBufCount(&queue) == 1 &&
                            bufferqueueGetBufLen(&queue) == 1 && bufferqueueFront(&queue) == ordinary &&
                            bufferqueueGetCharge(&queue) == sbufGetQueueCharge(ordinary),
                        "refused splice insertion consumed ownership, data, or queue state");
            }
        }
        bufferqueuePushBack(&queue, bufferpoolGetSpliceBuffer(env.buffers));
        bufferqueuePushBack(&queue, makeSpliceWriteBuffer(&env, source, sockets[1], "", "header"));
        require(bufferqueuePushBack(&queue, buf) == buf, "queue replaced a splice allocation");
        pipe_read_fd                    = metadata.pipefd[0];
        pipe_read_error                 = mode == 1 ? EINTR : mode == 2 ? EIO : 0;
        const unsigned int pipes_before = pipe_calls;
        bufferqueueDestroy(&queue);
        require(bufferqueueGetCharge(&queue) == 0 && bufferqueueGetBufLen(&queue) == 0 &&
                    bufferqueueGetBufCount(&queue) == 0,
                "queue destruction retained accounting or entries");
        require(pipe_read_error == 0 && pipe_calls == pipes_before,
                "queue cleanup skipped its drain or created a pipe");
        pipe_read_fd = -1;
        if (mode == 2)
        {
            requireClosed(metadata.pipefd[0]);
            requireClosed(metadata.pipefd[1]);
        }
        sbuf_t *reused = bufferpoolGetSpliceBuffer(env.buffers);
        require(reused == buf && sbufSpliceIsReusable(reused), "queue destruction leaked its last splice wrapper");
        if (mode == 2)
        {
            require(sbufSpliceMetadata(reused).pipefd[0] >= 0 && sbufSpliceMetadata(reused).pipefd[1] >= 0 &&
                        pipe_calls == pipes_before + 1,
                    "checkout did not replace the pair closed after a failed drain");
        }
        else
        {
            require(sbufSpliceMetadata(reused).pipefd[0] == metadata.pipefd[0] &&
                        sbufSpliceMetadata(reused).pipefd[1] == metadata.pipefd[1] &&
                        fcntl(metadata.pipefd[0], F_GETFD) >= 0 && fcntl(metadata.pipefd[1], F_GETFD) >= 0,
                    "queue destruction discarded a healthy reusable pipe");
        }
        bufferpoolReuseBuffer(env.buffers, reused);
        sbuf_t *fresh = makeSpliceWriteBuffer(&env, source, sockets[1], "NEW", "");
        sbuf_t *dest  = bufferpoolGetLargeBuffer(env.buffers);
        sbufSpliceMaterializeToBuffer(fresh, dest, env.buffers);
        require(sbufGetLength(dest) == 3 && memoryEqual(sbufGetRawPtr(dest), "NEW", 3),
                "queue cleanup left stale body bytes in a reused pipe");
        bufferpoolReuseBuffer(env.buffers, dest);
    }
    wioClose(source);
    close(sockets[1]);
    teardown(&env);
}

static void testSpliceMaterializationRetries(void)
{
    test_env_t env;
    setup(&env);
    bufferpoolUpdateAllocationPaddings(env.buffers, 64, 64, 64, 64);
    int    sockets[2];
    wio_t *source = socketIO(&env, sockets);
    for (unsigned int partial = 0; partial < 2; ++partial)
    {
        // Interrupt before reading, accumulate short reads, then interrupt after progress.
        for (unsigned int mode = 0; mode < 3; ++mode)
        {
            sbuf_t *buf  = makeSpliceWriteBuffer(&env, source, sockets[1], "123456789", "HEAD");
            sbuf_t *dest = bufferpoolGetLargeBuffer(env.buffers);
            sbufSetLength(dest, 2);
            sbufWrite(dest, ">>", 2);
            pipe_read_fd          = sbufSpliceMetadata(buf).pipefd[0];
            pipe_read_error       = mode == 1 ? 0 : EINTR;
            pipe_read_limit       = mode == 0 ? SIZE_MAX : 2;
            pipe_read_calls       = 0;
            pipe_read_error_after = mode == 2 ? 1 : 0;
            if (partial)
            {
                require(sbufSpliceReadToBuffer(buf, dest, 7) == dest && sbufGetLength(dest) == 9 &&
                            memoryEqual(sbufGetRawPtr(dest), ">>HEAD123", 9) && dest->curpos == 64,
                        "partial retries changed appended bytes or destination padding");
                int available = -1;
                require(sbufGetLength(buf) == 6 && buf->curpos == 64 && buf->capacity == 70 &&
                            ioctl(pipe_read_fd, FIONREAD, &available) == 0 && available == 6,
                        "partial retries changed the remaining private body or source accounting");
            }
            else
            {
                require(sbufSpliceMaterializeToBuffer(buf, dest, env.buffers) == dest && sbufGetLength(dest) == 13 &&
                            memoryEqual(sbufGetRawPtr(dest), "HEAD123456789", 13) && dest->curpos == 60,
                        "conversion retries changed payload order or left headroom");
            }
            const unsigned int expected_reads = mode == 0 ? 2 : (partial ? 2 : 5) + (mode == 2 ? 1 : 0);
            require(pipe_read_error == 0 && pipe_read_calls == expected_reads && dest->flags == 0 &&
                        sbufGetLeftPadding(dest) == 64,
                    "materialization failed to retry interrupted/short reads or preserve ordinary storage");
            pipe_read_fd          = -1;
            pipe_read_limit       = SIZE_MAX;
            pipe_read_error_after = 0;
            if (partial)
            {
                sbufSpliceMaterializeToBuffer(buf, dest, env.buffers);
                require(sbufGetLength(dest) == 6 && memoryEqual(sbufGetRawPtr(dest), "456789", 6),
                        "partial retry consumed bytes belonging to the remainder");
            }
            bufferpoolReuseBuffer(env.buffers, dest);
        }
    }
    wioClose(source);
    close(sockets[1]);
    teardown(&env);
}

static void testPrivateBodies(void)
{
    test_env_t env;
    setup(&env);
    bufferpoolUpdateAllocationPaddings(env.buffers, 64, 64, 64, 64);
    int          sockets[2];
    wio_t       *source = socketIO(&env, sockets);
    sbuf_t      *empty  = bufferpoolGetSpliceBuffer(env.buffers);
    require(empty != NULL, "failed to check out empty conversion fixture");
    sbufSpliceClosePipe(empty);
    unsigned int before      = pipe_calls;
    sbuf_t      *prefix_dest = bufferpoolGetLargeBuffer(env.buffers);
    require(sbufSpliceReadToBuffer(empty, prefix_dest, 0) == prefix_dest && sbufGetLength(empty) == 0 &&
                sbufGetLength(prefix_dest) == 0,
            "zero-byte partial read rejected an unused splice wrapper");
    sbufSpliceMaterializeToBuffer(empty, prefix_dest, env.buffers);
    require(sbufGetLength(prefix_dest) == 0 && prefix_dest->flags == 0 && pipe_calls == before,
            "empty conversion changed the payload or created a pipe");
    empty = bufferpoolGetSpliceBuffer(env.buffers);
    require(empty != NULL, "failed to check out prefix-only fixture");
    sbufSpliceClosePipe(empty);
    before = pipe_calls;
    sbufShiftLeft(empty, 2);
    sbufWrite(empty, "hi", 2);
    require(pipe_calls == before, "unused/prefix-only wrapper created a pipe");
    sbufSpliceReadToBuffer(empty, prefix_dest, 1);
    require(sbufGetLength(prefix_dest) == 1 && memoryEqual(sbufGetRawPtr(prefix_dest), "h", 1) &&
                sbufGetLength(empty) == 1 && empty->curpos == 63 && pipe_calls == before,
            "prefix-only partial read changed the remainder or created a pipe");
    sbufSpliceMaterializeToBuffer(empty, prefix_dest, env.buffers);
    require(sbufGetLength(prefix_dest) == 1 && memoryEqual(sbufGetRawPtr(prefix_dest), "i", 1) && pipe_calls == before,
            "prefix-only conversion needed a source or pipe");
    bufferpoolReuseBuffer(env.buffers, prefix_dest);
    require(wioEnableSplice(source) == 0 && pipe_calls == before, "enabling splice created a pipe");
    sbuf_t                  *a  = makeSpliceWriteBuffer(&env, source, sockets[1], "AAA", "a:");
    splice_buffer_metadata_t ma = sbufSpliceMetadata(a);
    require(pipe_calls == before + 1, "first transfer did not create a private pair");
    sbuf_t                  *b  = makeSpliceWriteBuffer(&env, source, sockets[1], "BBB", "b:");
    splice_buffer_metadata_t mb = sbufSpliceMetadata(b);
    require(ma.pipefd[0] != mb.pipefd[0], "bodies share a pipe or retain a source");
    wioClose(source);
    requireClosed(sockets[0]);
    int replacement[2];
    require(socketpair(AF_UNIX, SOCK_STREAM, 0, replacement) == 0, "replacement socketpair failed");
    require(replacement[0] == sockets[0], "source descriptor number was not reused");
    close(sockets[1]);
    sockets[1]   = replacement[1];
    source       = wioGet(env.loop, sockets[0]);
    sbuf_t *dest = bufferpoolGetLargeBuffer(env.buffers);
    sbufSpliceReadToBuffer(b, dest, 3);
    sbufSpliceReadToBuffer(b, dest, 2);
    require(sbufGetLength(dest) == 5 && memoryEqual(sbufGetRawPtr(dest), "b:BBB", 5),
            "reverse partial read mixed bodies");
    bufferpoolReuseBuffer(env.buffers, b);
    sbufSpliceMaterializeToBuffer(a, dest, env.buffers);
    require(memoryEqual(sbufGetRawPtr(dest), "a:AAA", 5), "reverse consumption damaged A");
    before = pipe_calls;
    a      = makeSpliceWriteBuffer(&env, source, sockets[1], "OLD", "prefix");
    ma     = sbufSpliceMetadata(a);
    require(pipe_calls == before, "empty pool reuse recreated a pipe");
    pipe_read_fd    = ma.pipefd[0];
    pipe_read_error = EINTR;
    bufferpoolReuseBuffer(env.buffers, a);
    require(pipe_read_error == 0, "discard did not retry EINTR");
    pipe_read_fd = -1;
    a        = makeSpliceWriteBuffer(&env, source, sockets[1], "NEW", "");
    require(sbufSpliceMetadata(a).pipefd[0] == ma.pipefd[0], "discard replaced a healthy pair");
    sbufSpliceMaterializeToBuffer(a, dest, env.buffers);
    require(sbufGetLength(dest) == 3 && memoryEqual(sbufGetRawPtr(dest), "NEW", 3), "discard left stale bytes");
    a           = makeSpliceWriteBuffer(&env, source, sockets[1], "BAD", "");
    ma          = sbufSpliceMetadata(a);
    pipe_read_fd    = ma.pipefd[0];
    pipe_read_error = EIO;
    bufferpoolReuseBuffer(env.buffers, a);
    requireClosed(ma.pipefd[0]);
    requireClosed(ma.pipefd[1]);
    before = pipe_calls;
    a = bufferpoolGetSpliceBuffer(env.buffers);
    require(a != NULL && sbufSpliceMetadata(a).pipefd[0] >= 0 && sbufSpliceIsReusable(a) && pipe_calls == before + 1,
            "checkout did not replace the pair closed after a failed drain");
    bufferpoolReuseBuffer(env.buffers, a);
    pipe_read_fd = -1;
    bufferpoolReuseBuffer(env.buffers, dest);
    wioClose(source);
    close(sockets[1]);
    teardown(&env);
}

static void testPrivateCancellation(void)
{
    // Direct rejection, overflow, queued error, forced close, close timeout, loop teardown.
    for (unsigned int mode = 0; mode < 6; ++mode)
    {
        test_env_t env;
        setup(&env);
        bufferpoolUpdateAllocationPaddings(env.buffers, 64, 64, 64, 64);
        int     source_fds[2], dest_fds[2];
        wio_t  *source = socketIO(&env, source_fds);
        wio_t  *dest   = socketIO(&env, dest_fds);
        sbuf_t *a      = makeSpliceWriteBuffer(&env, source, source_fds[1], "AAA", "prefix");
        sbuf_t *b      = makeSpliceWriteBuffer(&env, source, source_fds[1], "BBB", "");
        if (mode == 0)
        {
            require(wloopRequestQuiesce(env.loop), "failed to close write admission");
            require(wioWrite(dest, a) == -1, "closed admission accepted a write");
        }
        else
        {
            write_test_fd = dest_fds[0];
            send_error    = EAGAIN;
            if (mode == 1)
                dest->max_write_bufsize = 1;
            wioWrite(dest, a);
            if (mode == 2)
            {
                send_error = EPIPE;
                wloopProcessEvents(env.loop, 0);
            }
            else if (mode == 3)
                wioFree(dest);
            else if (mode == 4)
            {
                wioClose(dest);
                require(dest->close_timer != NULL, "close timeout was not armed");
                dest->close_timer->cb((wevent_t *) dest->close_timer);
            }
        }
        sbuf_t *real = bufferpoolGetLargeBuffer(env.buffers);
        sbufSpliceMaterializeToBuffer(b, real, env.buffers);
        require(sbufGetLength(real) == 3 && memoryEqual(sbufGetRawPtr(real), "BBB", 3),
                "canceling A damaged B's private body");
        bufferpoolReuseBuffer(env.buffers, real);
        write_test_fd = -1;
        send_error = splice_error = 0;
        close(source_fds[1]);
        close(dest_fds[1]);
        teardown(&env);
    }
}

static void countWriteCallback(wio_t *io)
{
    unsigned int *calls = weventGetUserdata(io);
    ++*calls;
}

typedef enum splice_write_case_e
{
    kWritePiped,
    kWriteEmpty,
    kWritePrefixOnly,
    kWriteShortPrefix,
    kWriteShortBody,
    kWriteBodyAgain,
    kWritePrefixInterrupted,
    kWriteBodyInterrupted,
    kWriteMixedQueue,
    kWriteGracefulClose,
    kWriteSocketBackpressure
} splice_write_case_t;

static void testSpliceWrite(splice_write_case_t kind)
{
    test_env_t env;
    setup(&env);
    bufferpoolUpdateAllocationPaddings(env.buffers, 64, 64, 64, 64);
    int    source_fds[2], destination_fds[2];
    wio_t *source      = socketIO(&env, source_fds);
    wio_t *destination = socketIO(&env, destination_fds);
    require(wioEnableSplice(source) == 0, "failed to enable splice writes");
    unsigned int callbacks = 0;
    weventSetUserData(destination, &callbacks);
    wioSetCallBackWrite(destination, countWriteCallback);
    const char *body   = kind == kWriteEmpty || kind == kWritePrefixOnly ? "" : "123456789";
    const char *prefix = kind == kWriteEmpty || kind == kWriteBodyInterrupted ? ""
                         : kind == kWriteShortPrefix                          ? "HEADHEAD"
                                                                              : "HEAD";
    char        expected[64];
    snprintf(expected, sizeof(expected), "%s%s", prefix, body);
    sbuf_t *buf         = makeSpliceWriteBuffer(&env, source, source_fds[1], body, prefix);
    write_test_fd       = destination_fds[0];
    int    first_write  = (int) strlen(expected);
    size_t filler_bytes = 0;
    switch (kind)
    {
    case kWriteShortPrefix:
        send_limit   = 2;
        splice_error = EAGAIN; // Reached only after several queued prefix writes.
        first_write  = 2;
        break;
    case kWriteShortBody:
        splice_limit = 3;
        first_write  = 7;
        break;
    case kWriteBodyAgain:
    case kWriteMixedQueue:
    case kWriteGracefulClose:
        splice_error = EAGAIN;
        first_write  = 4;
        break;
    case kWritePrefixInterrupted:
        send_error  = EINTR;
        first_write = 0;
        break;
    case kWriteBodyInterrupted:
        splice_error = EINTR;
        first_write  = 0;
        break;
    case kWriteSocketBackpressure: {
        const int size = 4096;
        require(setsockopt(destination_fds[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0,
                "failed to bound the destination send buffer");
        char filler[512];
        memset(filler, 'x', sizeof(filler));
        ssize_t sent;
        while ((sent = send(destination_fds[0], filler, sizeof(filler), 0)) > 0)
        {
            filler_bytes += (size_t) sent;
            require(filler_bytes < 1024U * 1024U, "destination send buffer did not fill");
        }
        require(sent == -1 && errno == EAGAIN && filler_bytes != 0, "failed to create actual socket backpressure");
        first_write = 0;
        break;
    }
    default:
        break;
    }
    require(wioWrite(destination, buf) == first_write, "splice write returned incorrect progress");
    const bool queued = first_write < (int) strlen(expected);
    require(destination->write_bufsize == strlen(expected) - (size_t) first_write,
            "splice queue has incorrect remaining-byte accounting");
    if (queued)
    {
        require(*write_queue_front(&destination->write_queue) == buf && buf->flags == kSbufFlagSplice,
                "splice remainder was not queued as a pipe-backed wrapper");
        const uint32_t prefix_sent = min((uint32_t) first_write, (uint32_t) strlen(prefix));
        require(buf->curpos == 64U - strlen(prefix) + prefix_sent &&
                    buf->capacity == 64U + strlen(body) - ((uint32_t) first_write - prefix_sent),
                "partial write moved the descriptor cursor or retained incorrect logical capacity");
    }
    if (kind == kWriteBodyAgain)
    {
        splice_error = EINTR; // The first queued retry must also preserve the remainder.
    }
    if (kind == kWriteMixedQueue)
    {
        sbuf_t *independent = makeSpliceWriteBuffer(&env, source, source_fds[1], "BBB", "b:");
        sbuf_t *converted   = bufferpoolGetLargeBuffer(env.buffers);
        sbufSpliceMaterializeToBuffer(independent, converted, env.buffers);
        require(memoryEqual(sbufGetRawPtr(converted), "b:BBB", 5), "B conversion consumed queued A");
        bufferpoolReuseBuffer(env.buffers, converted);
        sbuf_t *ordinary = bufferpoolGetSmallBuffer(env.buffers);
        sbufSetLength(ordinary, 8);
        sbufWrite(ordinary, "|NORMAL|", 8);
        require(wioWrite(destination, ordinary) == 0, "ordinary data bypassed the older splice remainder");
        sbuf_t *next = makeSpliceWriteBuffer(&env, source, source_fds[1], "abc", "NEXT");
        require(wioWrite(destination, next) == 0, "queued second wrapper did not enter its private pipe");
        strcat(expected, "|NORMAL|NEXTabc");
        require(destination->write_bufsize == strlen(expected) - (size_t) first_write,
                "mixed write queue lost logical byte accounting");
    }
    wioClose(source);
    requireClosed(source_fds[0]);
    if (kind == kWriteGracefulClose)
    {
        require(wioClose(destination) == 0 && ! wioIsClosed(destination), "graceful close discarded a splice queue");
    }
    while (filler_bytes != 0)
    {
        char    filler[512];
        ssize_t got = recv(destination_fds[1], filler, min(filler_bytes, sizeof(filler)), MSG_DONTWAIT);
        require(got > 0, "failed to drain the backpressure fixture");
        filler_bytes -= (size_t) got;
    }
    for (unsigned int attempt = 0; attempt < 16 && ! write_queue_empty(&destination->write_queue); ++attempt)
    {
        require(wloopProcessEvents(env.loop, 0) >= 0, "queued splice dispatch failed");
    }
    require(write_queue_empty(&destination->write_queue) && destination->write_bufsize == 0,
            "splice retry did not drain its queue");
    char         received[64];
    const size_t expected_bytes = strlen(expected);
    if (expected_bytes != 0)
    {
        require(recv(destination_fds[1], received, sizeof(received), MSG_DONTWAIT) == (ssize_t) expected_bytes &&
                    memoryEqual(received, expected, expected_bytes),
                "splice send changed prefix/body bytes or mixed FIFO ordering");
    }
    require(callbacks > 0, "splice write never delivered a progress callback");
    requireClosed(source_fds[0]);
    if (kind == kWriteGracefulClose)
    {
        require(wioIsClosed(destination), "graceful close did not finish after draining");
    }
    wioClose(destination);
    close(source_fds[1]);
    close(destination_fds[1]);
    write_test_fd = -1;
    send_limit = splice_limit = SIZE_MAX;
    require(send_error == 0 && splice_error == 0, "write fixture did not reach its injected error");
    teardown(&env);
}

static void testSpliceReads(void)
{
    runSpliceCase(kSpliceConvertPipe, 4096, 4097);
    runSpliceCase(kSpliceConvertPipe, 2 * LARGE_BUFFER_SIZE_RAM_HIGH, LARGE_BUFFER_SIZE_RAM_HIGH + 17);
    runSpliceCase(kSpliceConvertPipe, 4096, 9);
    runSpliceCase(kSplicePartialPipe, 4096, 9);
    runSpliceCase(kSpliceRetainPipe, 4096, 9);
    runSpliceCase(kSpliceRetainPartial, 4096, 9);
    runSpliceCase(kSpliceCloseBeforeRecycle, 4096, 9);
    runSpliceCase(kSpliceCloseAfterRecycle, 4096, 9);
    runSpliceCase(kSpliceForwardWrite, 4096, 9);
    runSpliceCase(kSpliceDisabled, 4096, 9);
    runSpliceCase(kSpliceDisabled, 4096, 9000);
    runSpliceCase(kSpliceDroppedPayload, 4096, 9);
    runSpliceCase(kSpliceDirectRecycleEmpty, 4096, 9);
    runSpliceCase(kSpliceRecycleUnused, 4096, 9);
    runSpliceCase(kSpliceWriteError, 4096, 9);
    runSpliceCase(kSpliceWriteCloseQueue, 4096, 9);
    runSpliceCase(kSpliceWriteClosed, 4096, 9);

    const struct
    {
        splice_case_t kind;
        const char   *diagnostic;
    } failures[] = {
        {kSpliceSmallDestination, "destination too small"},
        {kSplicePartialRange, "requested bytes or prefix exceed source length"},
        {kSplicePartialCapacity, "destination has insufficient append space"},
#if BUFFER_POOL_DEBUG == 1
        {kSpliceResidualPipe, "splice payload and pipe must be empty"},
#endif
        {kSpliceShortPipe, "incomplete read from pipe (requested=10, consumed=9, result=-1"},
        {kSpliceShortPartial, "incomplete read from pipe (requested=10, consumed=9, result=-1"},
        {kSpliceEOFPipe, "incomplete read from pipe (requested=10, consumed=9, result=0"},
        {kSpliceEOFPartial, "incomplete read from pipe (requested=10, consumed=9, result=0"},
        {kSpliceFailedRead, "incomplete read from pipe (requested=9, consumed=0, result=-1"},
        {kSpliceFailedPartial, "incomplete read from pipe (requested=9, consumed=2, result=-1"},
        {kSpliceInvalidFlags, "requires kSbufFlagSplice"},
        {kSpliceWriteRawIP, "splice buffers require a TCP or UDP destination"},
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

typedef struct ordinary_read_probe_s
{
    buffer_pool_t *pool;
    uint32_t       expected_capacity;
    uint32_t       received;
} ordinary_read_probe_t;

static void bestFitRead(wio_t *io, sbuf_t *buf)
{
    ordinary_read_probe_t *probe = weventGetUserdata(io);
    require(! wioIsSpliceEnabled(io) && buf->flags == 0, "best-fit read used splice");
    require(sbufGetTotalCapacityNoPadding(buf) == probe->expected_capacity && buf->curpos == 64,
            "best-fit read chose the wrong tier or padding");
    const uint8_t *payload = sbufGetRawPtr(buf);
    for (uint32_t i = 0; i < sbufGetLength(buf); ++i)
        require(payload[i] == 0x5A, "best-fit read corrupted payload");
    probe->received += sbufGetLength(buf);
    bufferpoolReuseBuffer(probe->pool, buf);
}

static void testOrdinaryBestFitRead(void)
{
    const uint32_t lengths[]    = {512, 4096, 65537, 512};
    const uint32_t capacities[] = {
        1024, MEDIUM_BUFFER_SIZE_RAM_HIGH, LARGE_BUFFER_SIZE_RAM_HIGH, LARGE_BUFFER_SIZE_RAM_HIGH};
    uint8_t payload[65537];
    memset(payload, 0x5A, sizeof(payload));
    for (size_t i = 0; i < ARRAY_SIZE(lengths); ++i)
    {
        test_env_t env;
        setupWithBufferSize(&env, LARGE_BUFFER_SIZE_RAM_HIGH);
        // Smaller tiers with insufficient headroom must not replace the large read buffer.
        bufferpoolUpdateAllocationPaddings(env.buffers, 64, i == 3 ? 0 : 64, i == 3 ? 32 : 64, 64);
        int                   sockets[2];
        wio_t                *io    = socketIO(&env, sockets);
        ordinary_read_probe_t probe = {.pool = env.buffers, .expected_capacity = capacities[i]};
        weventSetUserData(io, &probe);
        wioSetCallBackRead(io, bestFitRead);
        require(wioRead(io) == 0 && send(sockets[1], payload, lengths[i], 0) == (ssize_t) lengths[i],
                "failed to supply ordinary best-fit input");
        require(wloopProcessEvents(env.loop, 0) >= 0 && probe.received == lengths[i],
                "ordinary best-fit read failed to deliver the payload");
        close(sockets[1]);
        require(wloopProcessEvents(env.loop, 0) >= 0 && wioIsClosed(io),
                "zero available bytes prevented ordinary EOF handling");
        teardown(&env);
    }
}

static void testBufferQueueCharge(void)
{
    test_env_t env;
    setup(&env);
    buffer_queue_t queue;
    bufferqueueInitEmpty(&queue);
    require(bufferqueueGetCharge(&queue) == 0 && bufferqueueGetBufLen(&queue) == 0, "empty queue has stale accounting");
    sbuf_t *a     = sbufCreateWithPadding(97, 64);
    sbuf_t *b     = sbufCreateWithPadding(7, 32);
    sbuf_t *empty = sbufCreateWithPadding(47, 32);
    sbufSetLength(a, 3);
    sbufWrite(a, "abc", 3);
    sbufSetLength(b, 2);
    sbufWrite(b, "de", 2);
    const size_t charge = sbufGetQueueCharge(a) + sbufGetQueueCharge(b) + sbufGetQueueCharge(empty);
    a                   = bufferqueuePushBack(&queue, a);
    b                   = bufferqueuePushFront(&queue, b);
    empty               = bufferqueuePushBack(&queue, empty);
    require(bufferqueueGetCharge(&queue) == charge && bufferqueueGetBufLen(&queue) == 5 &&
                bufferqueueGetBufCount(&queue) == 3,
            "queue charge did not include ordinary capacity, padding and empty entries");

    buffer_queue_t moved = queue;
    bufferqueueInitEmpty(&queue);
    require(bufferqueueGetCharge(&queue) == 0 && bufferqueueGetCharge(&moved) == charge &&
                bufferqueueGetBufLen(&moved) == 5,
            "whole-queue ownership transfer lost charge or left it in the source");
    const size_t b_charge = sbufGetQueueCharge(b);
    require(bufferqueuePopFront(&moved) == b && bufferqueueGetCharge(&moved) == charge - b_charge,
            "pop did not release the queued charge");
    sbufShiftRight(b, 1);
    b = bufferqueuePushBack(&moved, b);
    require(bufferqueueGetCharge(&moved) == charge && bufferqueueGetBufLen(&moved) == 4,
            "partial ordinary consumption changed retained capacity charge");
    require(bufferqueuePopFront(&moved) == a && memoryEqual(sbufGetRawPtr(a), "abc", 3), "queue lost first payload");
    bufferpoolReuseBuffer(env.buffers, a);
    require(bufferqueuePopFront(&moved) == empty && sbufGetLength(empty) == 0, "queue discarded empty entry");
    bufferpoolReuseBuffer(env.buffers, empty);
    require(bufferqueuePopFront(&moved) == b && sbufGetLength(b) == 1 && sbufReadUI8(b) == 'e',
            "queue changed reinserted payload order or content");
    bufferpoolReuseBuffer(env.buffers, b);
    require(bufferqueueGetCharge(&moved) == 0 && bufferqueueGetBufLen(&moved) == 0, "drained queue retained charge");
    bufferqueueDestroy(&moved);

    /* Exercise representability without allocating SIZE_MAX bytes. Failed
     * admission must precede the Debug replacement and leave caller ownership. */
    a = sbufCreateWithPadding(16, 32);
    sbufSetLength(a, 1);
    sbufWrite(a, "X", 1);
    for (unsigned int front = 0; front < 2; ++front)
    {
        for (unsigned int bytes = 0; bytes < 2; ++bytes)
        {
            queue.total_charge = bytes ? 0 : SIZE_MAX;
            queue.total_len    = bytes ? SIZE_MAX : 0;
            sbuf_t    *input   = a;
            const bool accepted =
                front ? bufferqueueTryPushFront(&queue, &input) : bufferqueueTryPushBack(&queue, &input);
            require(! accepted && input == a && bufferqueueGetBufCount(&queue) == 0 && sbufReadUI8(a) == 'X' &&
                        bufferqueueGetCharge(&queue) == (bytes ? 0 : SIZE_MAX) &&
                        bufferqueueGetBufLen(&queue) == (bytes ? SIZE_MAX : 0),
                    "unrepresentable admission changed queue accounting or caller ownership");
        }
    }
    bufferqueueInitEmpty(&queue);
    a = bufferqueuePushBack(&queue, a);
#if WW_HAVE_SPLICE
    b = sbufCreateWithPadding(8, 32);
    for (unsigned int front = 0; front < 2; ++front)
    {
        sbuf_t *input         = b;
        fail_queue_allocation = true;
        const bool accepted = front ? bufferqueueTryPushFront(&queue, &input) : bufferqueueTryPushBack(&queue, &input);
        require(! accepted && ! fail_queue_allocation && input == b && bufferqueueFront(&queue) == a &&
                    bufferqueueGetCharge(&queue) == sbufGetQueueCharge(a) && bufferqueueGetBufLen(&queue) == 1,
                "failed ordinary insertion changed queue accounting or caller ownership");
    }
    bufferpoolReuseBuffer(env.buffers, b);
#endif
    bufferqueueDestroy(&queue);
    require(bufferqueueGetCharge(&queue) == 0 && bufferqueueGetBufLen(&queue) == 0 &&
                bufferqueueGetBufCount(&queue) == 0,
            "nonempty queue destruction did not reset accounting");
    testWorkerUnbindWID();
    bufferqueueDestroy(&queue);
    testWorkerBindWID(0);
    teardown(&env);
}

static void testSharedBudget(void)
{
    test_env_t env;
    setup(&env);
    buffer_queue_t a, b;
    bufferqueueInitEmpty(&a);
    bufferqueueInitEmpty(&b);
    sbuf_t *input = sbufCreateWithPadding(64, 32);
    sbufSetLength(input, 2);
    sbufWrite(input, "ab", 2);
    const size_t    charge = sbufGetQueueCharge(input);
    buffer_budget_t budget;
    bufferbudgetInit(&budget, (buffer_budget_cost_t) {2, charge, 1});
    require(bufferqueueTryAttachBudget(&a, &budget) && bufferqueueTryAttachBudget(&b, &budget), "empty attach");
    require(bufferqueueTryPushBack(&a, &input), "exact admission");
    sbuf_t *extra    = sbufCreate(1);
    sbuf_t *original = extra;
    require(! bufferqueueTryPushFront(&b, &extra) && extra == original, "shared refusal changed ownership");
    buffer_budget_reservation_t active = {0};
    input                              = bufferqueuePopFrontReserved(&a, &active);
    require(budget.used.charge == charge && budget.used.entries == 1 && a.total_charge == 0, "reserved pop uncharged");
    require(! bufferqueueTryPushBack(&b, &extra), "active allowance disappeared");
    sbufShiftRight(input, 1);
    bufferbudgetReservationSetBytes(&active, 1);
#if WW_HAVE_SPLICE
    for (unsigned front = 0; front < 2; ++front)
    {
        sbuf_t *before        = input;
        fail_queue_allocation = true;
        bool accepted         = front ? bufferqueueTryPushFrontReserved(&b, &input, &active)
                                      : bufferqueueTryPushBackReserved(&b, &input, &active);
        require(! accepted && ! fail_queue_allocation && input == before && active.budget == &budget &&
                    budget.used.bytes == 1 && sbufReadUI8(input) == 'b',
                "failed transfer lost reservation");
    }
#endif
    require(bufferqueueTryPushFrontReserved(&b, &input, &active) && active.budget == NULL, "reserved transfer");
    input = bufferqueuePopFrontReserved(&b, &active);
    require(bufferqueueTryPushBackReserved(&a, &input, &active), "reserved back transfer double charged");
    input = bufferqueuePopFrontReserved(&a, &active);
    require(bufferqueueTryPushBackReserved(&b, &input, &active), "reserved return transfer");
    bufferqueueDestroy(&a);
    require(budget.used.charge == charge, "sibling destruction erased usage");
    buffer_queue_t moved = b;
    bufferqueueInitEmpty(&b);
    bufferqueueDestroy(&b);
    require(moved.budget == &budget && budget.used.entries == 1, "move lost binding");
    bufferqueueDestroy(&moved);
    bufferbudgetAssertEmpty(&budget);
    require(moved.budget == NULL, "destroy retained binding");
    require(bufferqueueTryPushBack(&b, &extra), "unbound insertion");
    require(bufferqueueTryAttachBudget(&b, &budget), "populated attach");
    buffer_queue_t refused = bufferqueueCreate(1);
    extra                  = sbufCreate(1);
    require(bufferqueueTryPushBack(&refused, &extra), "unbound second insertion");
    require(! bufferqueueTryAttachBudget(&refused, &budget) && refused.budget == NULL && budget.used.entries == 1,
            "populated attach ignored sibling");
    bufferqueueDestroy(&refused);
    bufferqueueDestroy(&b);
    bufferbudgetAssertEmpty(&budget);

    bufferbudgetInit(&budget, (buffer_budget_cost_t) {SIZE_MAX, SIZE_MAX, 2});
    require(bufferqueueTryAttachBudget(&a, &budget) && bufferqueueTryAttachBudget(&b, &budget), "reattach");
    input = sbufCreateWithPadding(64, 32);
    extra = sbufCreate(1);
#if WW_HAVE_SPLICE
    for (unsigned front = 0; front < 2; ++front)
    {
        sbuf_t *before        = input;
        fail_queue_allocation = true;
        bool accepted         = front ? bufferqueueTryPushFront(&a, &input) : bufferqueueTryPushBack(&a, &input);
        require(! accepted && input == before && ! fail_queue_allocation && budget.used.entries == 0 &&
                    budget.used.charge == 0,
                "deque refusal leaked tentative acquisition");
    }
#endif
    require(bufferqueueTryPushBack(&a, &input) && bufferqueueTryPushBack(&b, &extra), "two sibling admission");
    const size_t sibling_charge = sbufGetQueueCharge(extra);
    bufferqueueDestroy(&a);
    require(budget.used.charge == sibling_charge && budget.used.entries == 1, "destroy erased nonempty sibling");
    bufferqueueDestroy(&b);
    bufferbudgetAssertEmpty(&budget);
    teardown(&env);
}

#if WW_HAVE_SPLICE
typedef struct splice_switch_probe_s
{
    unsigned calls;
    sbuf_t  *held;
} splice_switch_probe_t;

static void switchReadMode(wio_t *io, sbuf_t *buf)
{
    splice_switch_probe_t *probe = weventGetUserdata(io);
    const unsigned         step  = probe->calls++;
    require(step < 4 && sbufGetLength(buf) == 3 && sbufIsSplice(buf) == (step % 2 != 0),
            "read did not observe the selected representation");
    if (step == 1)
    {
        // Retain a private body across mode changes and subsequent reads.
        probe->held = buf;
        wioDisableSplice(io);
        return;
    }
    if (sbufIsSplice(buf))
        buf = sbufSpliceMaterializeToBuffer(buf, bufferpoolGetLargeBuffer(io->loop->bufpool), io->loop->bufpool);
    const char *expected[] = {"AAA", "BBB", "CCC", "DDD"};
    require(memoryEqual(sbufGetRawPtr(buf), expected[step], 3), "mode switch changed stream bytes");
    bufferpoolReuseBuffer(io->loop->bufpool, buf);
    if (step == 0)
        require(wioEnableSplice(io) == 0, "could not enable splice from an ordinary read callback");
    else if (step == 2)
    {
        wioReadStop(io);
        require(wioEnableSplice(io) == 0 && wioRead(io) == 0, "could not re-enable splice across read restart");
    }
    else
        wioDisableSplice(io);
}

static void testSpliceModeSwitch(void)
{
    test_env_t env;
    setup(&env);
    int                   sockets[2];
    wio_t                *io    = socketIO(&env, sockets);
    splice_switch_probe_t probe = {0};
    weventSetUserData(io, &probe);
    wioSetCallBackRead(io, switchReadMode);
    require(wioRead(io) == 0, "failed to start ordinary reads for mode switching");
    const char *bytes[] = {"AAA", "BBB", "CCC", "DDD"};
    for (unsigned step = 0; step < ARRAY_SIZE(bytes); ++step)
    {
        require(send(sockets[1], bytes[step], 3, 0) == 3, "failed to feed mode-switch input");
        for (unsigned attempt = 0; attempt < 32 && probe.calls == step; ++attempt)
            require(wloopProcessEvents(env.loop, 0) >= 0, "mode-switch dispatch failed");
        require(probe.calls == step + 1, "mode-switch input was not delivered");
    }
    require(! wioIsSpliceEnabled(io) && probe.held != NULL, "mode switch lost retained splice input");
    // The read preference must not change how a retained splice buffer is written.
    require(wioWrite(io, probe.held) == 3, "ordinary read mode rejected a splice write");
    char reply[3];
    require(recv(sockets[1], reply, sizeof(reply), MSG_DONTWAIT) == 3 && memoryEqual(reply, "BBB", 3),
            "retained body changed while switching modes");
    wioFree(io);
    close(sockets[1]);
    teardown(&env);
}
#endif

int main(void)
{
    testSharedBudget();
    testBufferQueueCharge();
    testOrdinaryBestFitRead();
    testPrimaryDescriptorZero();
    testPipeDescriptorZero();
    testPendingDescriptorReuse();
    testPendingDetachRejected();
#if WW_HAVE_SPLICE
    testSpliceModeSwitch();
    testDirectSpliceRead();
    testSpliceUrgentRead();
    testPipeCapacityPreference();
    testSpliceReuseValidation();
    testPipeCapacityRetry();
    testSpliceReadCapacityPreference();
    testSpliceBufferQueue();
    testSpliceQueueCleanupAndRefusal();
    testSplicePipeFallback();
    testSpliceMaterializationRetries();
    testPrivateBodies();
    testPrivateCancellation();
    testSpliceReads();
    testSpliceReadConditions();
    testDeferredSpliceReads();
    for (splice_write_case_t kind = kWritePiped; kind <= kWriteSocketBackpressure; ++kind)
    {
        testSpliceWrite(kind);
    }
#endif
    test_env_t env;
    setup(&env);
    testOwnedDescriptor(&env);
    testNoClose(&env);
    testFileDescriptor(&env);
    testCloseCallback(&env);
    teardown(&env);
    return 0;
}
