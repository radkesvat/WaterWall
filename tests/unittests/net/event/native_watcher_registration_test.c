/*
 * Covers: kqueue and Solaris event-port creation, registration failure and read-interest preservation.
 * Setup: A local socket pair and the platform backend. Only the next specified syscall failure is injected.
 * Checks: A creation failure leaves the loop retryable. After a failed write upgrade, the kernel still
 * delivers read readiness for the original registration.
 * CTest: waterwall.native_watcher_registration_unit
 */
#define iowatcherInit       fixtureWatcherInit
#define iowatcherAddEvent   fixtureWatcherAddEvent
#define iowatcherDelEvent   fixtureWatcherDelEvent
#define iowatcherPollEvents fixtureWatcherPollEvents
#define iowatcherCleanUp    fixtureWatcherCleanUp

#include "wevent.h"

#include "test_assert.h"
#include <sys/socket.h>
#include <unistd.h>

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static int next_error;

static int failSyscall(void)
{
    errno      = next_error;
    next_error = 0;
    return -1;
}

#if defined(EVENT_KQUEUE)
#include <sys/event.h>
static bool allow_first_filter;

static bool failKqueueChange(void)
{
    if (allow_first_filter)
    {
        allow_first_filter = false;
        return false;
    }
    return next_error != 0;
}

#define kqueue()    (next_error ? failSyscall() : kqueue())
#define kevent(...) (failKqueueChange() ? failSyscall() : kevent(__VA_ARGS__))
#include "../../../../ww/event/kqueue.c"
#undef kqueue
#undef kevent
#elif defined(EVENT_PORT)
#include <port.h>
#define port_create()       (next_error ? failSyscall() : port_create())
#define port_associate(...) (next_error ? failSyscall() : port_associate(__VA_ARGS__))
#include "../../../../ww/event/evport.c"
#undef port_create
#undef port_associate
#else
#error "This test requires the native kqueue or event-port backend"
#endif

int main(void)
{
    testCaseSet("native watcher registration");
    wloop_t loop = {0};
    next_error   = EMFILE;
    require(fixtureWatcherInit(&loop) == -EMFILE && loop.iowatcher == NULL, "failed creation published a watcher");
    require(fixtureWatcherInit(&loop) == 0, "failed watcher creation prevented retry");

    int pair[2];
    require(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "could not create local socket pair");
    int   fd = pair[0];
    wio_t io = {.loop = &loop, .fd = fd};
    io_array_init(&loop.ios, fd + 1);
    loop.ios.ptr[fd] = &io;
    next_error       = ENOSPC;
    require(fixtureWatcherAddEvent(&loop, fd, WW_READ) == -ENOSPC, "failed registration reported success");
#if defined(EVENT_KQUEUE)
    // Kqueue installs two filters for a fresh read/write watch. Fail the second native change.
    allow_first_filter = true;
    next_error         = ENOSPC;
    require(fixtureWatcherAddEvent(&loop, fd, WW_RDWR) == -ENOSPC, "partial registration reported success");
    require(fixtureWatcherDelEvent(&loop, fd, WW_READ) == -ENOENT, "partial registration left its read filter armed");
#endif
    require(fixtureWatcherAddEvent(&loop, fd, WW_READ) == 0, "read registration could not be retried");
    io.events  = WW_READ;
    loop.nios  = 1;
    next_error = ENOSPC;
    require(fixtureWatcherAddEvent(&loop, fd, WW_WRITE) == -ENOSPC, "failed write upgrade reported success");
    require(write(pair[1], "r", 1) == 1, "could not signal the original read registration");
    require(fixtureWatcherPollEvents(&loop, 1000) == 1 && io.pending && io.revents == WW_READ,
            "failed upgrade changed the original read registration");

    require(fixtureWatcherDelEvent(&loop, fd, WW_READ) == 0, "could not remove the read registration");
    require(fixtureWatcherCleanUp(&loop) == 0, "watcher cleanup failed");
    io_array_cleanup(&loop.ios);
    close(pair[0]);
    close(pair[1]);
    return 0;
}
