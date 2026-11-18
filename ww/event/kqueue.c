#include "iowatcher.h"

#ifdef EVENT_KQUEUE
#include "ev_memory.h"
#include "loggers/internal_logger.h"
#include "wevent.h"
#include "wmath.h"

#include <sys/event.h>

#define EVENTS_INIT_SIZE 64

typedef struct kqueue_ctx_s
{
    int            kqfd;
    int            capacity;
    struct kevent *events;
} kqueue_ctx_t;

int iowatcherInit(wloop_t *loop)
{
    if (loop->iowatcher)
        return 0;

    int fd = kqueue();
    if (fd < 0)
        return -errno;

    kqueue_ctx_t *ctx;
    EVENTLOOP_ALLOC_SIZEOF(ctx);
    ctx->kqfd     = fd;
    ctx->capacity = EVENTS_INIT_SIZE;
    EVENTLOOP_ALLOC(ctx->events, (size_t) ctx->capacity * sizeof(*ctx->events));
    loop->iowatcher = ctx;
    return 0;
}

int iowatcherCleanUp(wloop_t *loop)
{
    kqueue_ctx_t *ctx = loop->iowatcher;
    if (ctx)
    {
        close(ctx->kqfd);
        EVENTLOOP_FREE(ctx->events);
        EVENTLOOP_FREE(loop->iowatcher);
    }
    return 0;
}

static int kqueueChangeFilter(int queue_fd, int fd, short filter, unsigned short flags)
{
    struct kevent change = {0};
    EV_SET(&change, (uintptr_t) fd, filter, flags, 0, 0, NULL);
    int result;
    do
    {
        result = kevent(queue_fd, &change, 1, NULL, 0, NULL);
    } while (result < 0 && errno == EINTR);
    return result < 0 ? -errno : 0;
}

int iowatcherAddEvent(wloop_t *loop, int fd, int events)
{
    int result = iowatcherInit(loop);
    if (result != 0)
        return result;
    kqueue_ctx_t *ctx = loop->iowatcher;

    if (events & WW_READ)
    {
        result = kqueueChangeFilter(ctx->kqfd, fd, EVFILT_READ, EV_ADD);
        if (result != 0)
            return result;
    }
    if (events & WW_WRITE)
    {
        result = kqueueChangeFilter(ctx->kqfd, fd, EVFILT_WRITE, EV_ADD);
        if (result != 0 && (events & WW_READ))
        {
            /* The caller supplies only new interests. Undo this call's read filter. */
            int rollback = kqueueChangeFilter(ctx->kqfd, fd, EVFILT_READ, EV_DELETE);
            if (rollback != 0 && rollback != -ENOENT)
            {
                LOGF("kqueue: could not roll back read registration (fd=%d, error=%d)", fd, -rollback);
                abortProgramNow(1);
            }
        }
    }
    return result;
}

int iowatcherDelEvent(wloop_t *loop, int fd, int events)
{
    kqueue_ctx_t *ctx = loop->iowatcher;
    if (ctx == NULL)
        return 0;
    int read_error  = (events & WW_READ) ? kqueueChangeFilter(ctx->kqfd, fd, EVFILT_READ, EV_DELETE) : 0;
    int write_error = (events & WW_WRITE) ? kqueueChangeFilter(ctx->kqfd, fd, EVFILT_WRITE, EV_DELETE) : 0;
    return read_error != 0 ? read_error : write_error;
}

int iowatcherPollEvents(wloop_t *loop, int timeout)
{
    kqueue_ctx_t *ctx = loop->iowatcher;
    if (ctx == NULL || loop->nios == 0)
        return 0;
    /* Each active descriptor can report one read and one write filter. */
    int max_events = (int) loop->nios * 2;
    if (max_events > ctx->capacity)
    {
        int capacity = (int) ceil2e((unsigned) max_events);
        ctx->events  = eventloopRealloc(
            ctx->events, (size_t) capacity * sizeof(*ctx->events), (size_t) ctx->capacity * sizeof(*ctx->events));
        ctx->capacity = capacity;
    }
    struct timespec ts = {0};
    if (timeout >= 0)
    {
        ts.tv_sec  = timeout / 1000;
        ts.tv_nsec = (timeout % 1000) * 1000000;
    }
    int count = kevent(ctx->kqfd, NULL, 0, ctx->events, ctx->capacity, timeout >= 0 ? &ts : NULL);
    if (count < 0)
        return errno == EINTR ? 0 : -errno;

    for (int i = 0; i < count; ++i)
    {
        const struct kevent *event = &ctx->events[i];
        if (event->flags & EV_ERROR)
            return event->data != 0 ? -(int) event->data : -EIO;
        wio_t *io = loop->ios.ptr[event->ident];
        if (io)
        {
            io->revents |= event->filter == EVFILT_READ ? WW_READ : WW_WRITE;
            EVENT_PENDING(io);
        }
    }
    return count;
}
#else
typedef int ww_kqueue_dummy_t;
#endif
