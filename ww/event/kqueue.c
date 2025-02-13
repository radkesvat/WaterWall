#include "iowatcher.h"

#ifdef EVENT_KQUEUE
#include "wplatform.h"

#if defined(COMPILER_CLANG)
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wsign-compare"
#elif defined(COMPILER_GCC)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wsign-compare"
#endif


#include "wdef.h"

#include <sys/event.h>

#include "wevent.h"

#define EVENTS_INIT_SIZE     64

#define READ_INDEX  0
#define WRITE_INDEX 1
#define EVENT_INDEX(type) ((type == EVFILT_READ) ? READ_INDEX : WRITE_INDEX)

typedef struct kqueue_ctx_s {
    int kqfd;
    int capacity;
    int nchanges;
    struct kevent* changes;
    //int nevents; // nevents == nchanges
    struct kevent* events;
} kqueue_ctx_t;

static void kqueue_ctx_resize(kqueue_ctx_t* kqueue_ctx, int size) {
    int bytes = (int)(sizeof(struct kevent) * (size_t)size);
    int oldbytes = (int)(sizeof(struct kevent) * (size_t)kqueue_ctx->capacity);
    kqueue_ctx->changes = (struct kevent*)eventloopRealloc(kqueue_ctx->changes,(size_t) bytes, (size_t)oldbytes);
    kqueue_ctx->events = (struct kevent*)eventloopRealloc(kqueue_ctx->events,(size_t) bytes, (size_t)oldbytes);
    kqueue_ctx->capacity = size;
}

int iowatcherInit(wloop_t* loop) {
    if (loop->iowatcher) return 0;
    kqueue_ctx_t* kqueue_ctx;
    EVENTLOOP_ALLOC_SIZEOF(kqueue_ctx);
    kqueue_ctx->kqfd = kqueue();
    kqueue_ctx->capacity = EVENTS_INIT_SIZE;
    kqueue_ctx->nchanges = 0;
    int bytes = (int) (sizeof(struct kevent) * (size_t)kqueue_ctx->capacity);
    EVENTLOOP_ALLOC(kqueue_ctx->changes,(size_t) bytes);
    EVENTLOOP_ALLOC(kqueue_ctx->events, (size_t)bytes);
    loop->iowatcher = kqueue_ctx;
    return 0;
}

int iowatcherCleanUp(wloop_t* loop) {
    if (loop->iowatcher == NULL) return 0;
    kqueue_ctx_t* kqueue_ctx = (kqueue_ctx_t*)loop->iowatcher;
    close(kqueue_ctx->kqfd);
    EVENTLOOP_FREE(kqueue_ctx->changes);
    EVENTLOOP_FREE(kqueue_ctx->events);
    EVENTLOOP_FREE(loop->iowatcher);
    return 0;
}

static int __add_event(wloop_t* loop, int fd, int event) {
    if (loop->iowatcher == NULL) {
        iowatcherInit(loop);
    }
    kqueue_ctx_t* kqueue_ctx = (kqueue_ctx_t*)loop->iowatcher;
    wio_t* io = loop->ios.ptr[fd];
    int idx = io->event_index[EVENT_INDEX(event)];
    if (idx < 0) {
        io->event_index[EVENT_INDEX(event)] = idx = kqueue_ctx->nchanges;
        kqueue_ctx->nchanges++;
        if (idx == kqueue_ctx->capacity) {
            kqueue_ctx_resize(kqueue_ctx, kqueue_ctx->capacity*2);
        }
        memorySet(kqueue_ctx->changes+idx, 0, sizeof(struct kevent));
        kqueue_ctx->changes[idx].ident = (uintptr_t)fd;
    }
    assert(kqueue_ctx->changes[idx].ident == fd);
    kqueue_ctx->changes[idx].filter = (int16_t)event;
    kqueue_ctx->changes[idx].flags = EV_ADD|EV_ENABLE;
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 0;
    kevent(kqueue_ctx->kqfd, kqueue_ctx->changes, kqueue_ctx->nchanges, NULL, 0, &ts);
    return 0;
}

int iowatcherAddEvent(wloop_t* loop, int fd, int events) {
    if (events & WW_READ) {
        __add_event(loop, fd, EVFILT_READ);
    }
    if (events & WW_WRITE) {
        __add_event(loop, fd, EVFILT_WRITE);
    }
    return 0;
}

static int __del_event(wloop_t* loop, int fd, int event) {
    kqueue_ctx_t* kqueue_ctx = (kqueue_ctx_t*)loop->iowatcher;
    if (kqueue_ctx == NULL) return 0;
    wio_t* io = loop->ios.ptr[fd];
    int idx = io->event_index[EVENT_INDEX(event)];
    if (idx < 0) return 0;
    assert(kqueue_ctx->changes[idx].ident == fd);
    kqueue_ctx->changes[idx].flags = EV_DELETE;
    io->event_index[EVENT_INDEX(event)] = -1;
    int lastidx = kqueue_ctx->nchanges - 1;
    if (idx < lastidx) {
        // swap
        struct kevent tmp;
        tmp = kqueue_ctx->changes[idx];
        kqueue_ctx->changes[idx] = kqueue_ctx->changes[lastidx];
        kqueue_ctx->changes[lastidx] = tmp;
        wio_t* last = loop->ios.ptr[kqueue_ctx->changes[idx].ident];
        if (last) {
            last->event_index[EVENT_INDEX(kqueue_ctx->changes[idx].filter)] = idx;
        }
    }
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 0;
    kevent(kqueue_ctx->kqfd, kqueue_ctx->changes, kqueue_ctx->nchanges, NULL, 0, &ts);
    kqueue_ctx->nchanges--;
    return 0;
}

int iowatcherDelEvent(wloop_t* loop, int fd, int events) {
    if (events & WW_READ) {
        __del_event(loop, fd, EVFILT_READ);
    }
    if (events & WW_WRITE) {
        __del_event(loop, fd, EVFILT_WRITE);
    }
    return 0;
}

int iowatcherPollEvents(wloop_t* loop, int timeout) {
    kqueue_ctx_t* kqueue_ctx = (kqueue_ctx_t*)loop->iowatcher;
    if (kqueue_ctx == NULL) return 0;
    if (kqueue_ctx->nchanges == 0) return 0;
    struct timespec ts, *tp;
    if (timeout == (int)INFINITE) {
        tp = NULL;
    }
    else {
        ts.tv_sec = timeout / 1000;
        ts.tv_nsec = (timeout % 1000) * 1000000;
        tp = &ts;
    }
    int nkqueue = kevent(kqueue_ctx->kqfd, kqueue_ctx->changes, kqueue_ctx->nchanges, kqueue_ctx->events, kqueue_ctx->nchanges, tp);
    if (nkqueue < 0) {
        printError("kevent");
        return nkqueue;
    }
    if (nkqueue == 0) return 0;
    int nevents = 0;
    for (int i = 0; i < nkqueue; ++i) {
        if (kqueue_ctx->events[i].flags & EV_ERROR) {
            continue;
        }
        ++nevents;
        int fd = (int) kqueue_ctx->events[i].ident;
        int revents = kqueue_ctx->events[i].filter;
        wio_t* io = loop->ios.ptr[fd];
        if (io) {
            if (revents & EVFILT_READ) {
                io->revents |= WW_READ;
            }
            if (revents & EVFILT_WRITE) {
                io->revents |= WW_WRITE;
            }
            EVENT_PENDING(io);
        }
        if (nevents == nkqueue) break;
    }
    return nevents;
}

#if defined(COMPILER_CLANG)
    #pragma clang diagnostic pop
#elif defined(COMPILER_GCC)
    #pragma GCC diagnostic pop
#endif

#endif
