#include "wloop.h"
#include "wevent.h"
#include "iowatcher.h"

#include "wdef.h"
#include "ev_memory.h"
#include "wlog.h"
#include "wmath.h"
#include "wtime.h"
#include "wsocket.h"
#include "wthread.h"

#if defined(OS_UNIX) && HAVE_EVENTFD
#include "sys/eventfd.h"
#endif

#define WLOOP_PAUSE_TIME 10      // ms
#define WLOOP_MAX_BLOCK_TIME 100 // ms
#define WLOOP_STAT_TIMEOUT 60000 // ms

#define IO_ARRAY_INIT_SIZE 1024
#define CUSTOM_EVENT_QUEUE_INIT_SIZE 16

#define EVENTFDS_READ_INDEX 0
#define EVENTFDS_WRITE_INDEX 1

static void __widle_del(widle_t* idle);
static void __wtimer_del(wtimer_t* timer);

static int timersCompare(const struct heap_node* lhs, const struct heap_node* rhs) {
    return TIMER_ENTRY(lhs)->next_timeout < TIMER_ENTRY(rhs)->next_timeout;
}

static int wloopProcessIdles(wloop_t* loop) {
    int nidles = 0;
    struct list_node* node = loop->idles.next;
    widle_t* idle = NULL;
    while (node != &loop->idles) {
        idle = IDLE_ENTRY(node);
        node = node->next;
        if (idle->repeat != INFINITE) {
            --idle->repeat;
        }
        if (idle->repeat == 0) {
            // NOTE: Just mark it as destroy and remove from list.
            // Real deletion occurs after wloopProcessPendings.
            __widle_del(idle);
        }
        EVENT_PENDING(idle);
        ++nidles;
    }
    return nidles;
}

static int __wloop_process_timers(struct heap* timers, uint64_t timeout) {
    int ntimers = 0;
    wtimer_t* timer = NULL;
    while (timers->root) {
        // NOTE: root of minheap has min timeout.
        timer = TIMER_ENTRY(timers->root);
        if (timer->next_timeout > timeout) {
            break;
        }
        if (timer->repeat != INFINITE) {
            --timer->repeat;
        }
        if (timer->repeat == 0) {
            // NOTE: Just mark it as destroy and remove from heap.
            // Real deletion occurs after wloopProcessPendings.
            __wtimer_del(timer);
        }
        else {
            // NOTE: calc next timeout, then re-insert heap.
            heap_dequeue(timers);
            if (timer->event_type == WEVENT_TYPE_TIMEOUT) {
                while (timer->next_timeout <= timeout) {
                    timer->next_timeout += (uint64_t)((htimeout_t*)timer)->timeout * 1000;
                }
            }
            else if (timer->event_type == WEVENT_TYPE_PERIOD) {
                hperiod_t* period = (hperiod_t*)timer;
                timer->next_timeout = (uint64_t)cronNextTimeout(period->minute, period->hour, period->day, period->week, period->month) * 1000000;
            }
            heap_insert(timers, &timer->node);
        }
        EVENT_PENDING(timer);
        ++ntimers;
    }
    return ntimers;
}

static int wloopProcessTimers(wloop_t* loop) {
    uint64_t now = wloopNowUS(loop);
    int ntimers = __wloop_process_timers(&loop->timers, loop->cur_hrtime);
    ntimers += __wloop_process_timers(&loop->realtimers, now);
    return ntimers;
}

static int wloopProcessIOS(wloop_t* loop, int timeout) {
    // That is to call IO multiplexing function such as select, poll, epoll, etc.
    int nevents = iowatcherPollEvents(loop, timeout);
    if (nevents < 0) {
        wlogd("poll_events error=%d", -nevents);
    }
    return nevents < 0 ? 0 : nevents;
}

static int wloopProcessPendings(wloop_t* loop) {
    if (loop->npendings == 0) return 0;

    wevent_t* cur = NULL;
    wevent_t* next = NULL;
    int ncbs = 0;
    // NOTE: invoke event callback from high to low sorted by priority.
    for (int i = WEVENT_PRIORITY_SIZE - 1; i >= 0; --i) {
        cur = loop->pendings[i];
        while (cur) {
            next = cur->pending_next;
            if (cur->pending) {
                if (cur->active && cur->cb) {
                    cur->cb(cur);
                    ++ncbs;
                }
                cur->pending = 0;
                // NOTE: Now we can safely delete event marked as destroy.
                if (cur->destroy) {
                    EVENT_DEL(cur);
                }
            }
            cur = next;
        }
        loop->pendings[i] = NULL;
    }
    loop->npendings = 0;
    return ncbs;
}

// wloopProcessIOS -> wloopProcessTimers -> wloopProcessIdles -> wloopProcessPendings
int wloopProcessEvents(wloop_t* loop, int timeout_ms) {
    // ios -> timers -> idles
    int nios, ntimers, nidles;
    nios = ntimers = nidles = 0;

    // calc blocktime
    int32_t blocktime_ms = timeout_ms;
    if (loop->ntimers) {
        wloopUpdateTime(loop);
        int64_t blocktime_us = blocktime_ms * 1000;
        if (loop->timers.root) {
            int64_t min_timeout = TIMER_ENTRY(loop->timers.root)->next_timeout - loop->cur_hrtime;
            blocktime_us = min(blocktime_us, min_timeout);
        }
        if (loop->realtimers.root) {
            int64_t min_timeout = TIMER_ENTRY(loop->realtimers.root)->next_timeout - wloopNowUS(loop);
            blocktime_us = min(blocktime_us, min_timeout);
        }
        if (blocktime_us < 0) goto process_timers;
        blocktime_ms = blocktime_us / 1000 + 1;
        blocktime_ms = min(blocktime_ms, timeout_ms);
    }

    if (loop->nios) {
        nios = wloopProcessIOS(loop, blocktime_ms);
    }
    else {
        hv_msleep(blocktime_ms);
    }
    wloopUpdateTime(loop);
    // wakeup by wloopStop
    if (loop->status == WLOOP_STATUS_STOP) {
        return 0;
    }

process_timers:
    if (loop->ntimers) {
        ntimers = wloopProcessTimers(loop);
    }

    int npendings = loop->npendings;
    if (npendings == 0) {
        if (loop->nidles) {
            nidles = wloopProcessIdles(loop);
        }
    }
    int ncbs = wloopProcessPendings(loop);
    printd("blocktime=%d nios=%d/%u ntimers=%d/%u nidles=%d/%u nactives=%d npendings=%d ncbs=%d\n", blocktime, nios, loop->nios, ntimers, loop->ntimers, nidles,
           loop->nidles, loop->nactives, npendings, ncbs);
    (void)nios;
    return ncbs;
}

static void wloopStatTimerCallBack(wtimer_t* timer) {
    wloop_t* loop = timer->loop;
    // wlog_set_level(LOG_LEVEL_DEBUG);
    wlogd("[loop] pid=%ld tid=%ld uptime=%lluus cnt=%llu nactives=%u nios=%u ntimers=%u nidles=%u", loop->pid, loop->tid,
          (unsigned long long)loop->cur_hrtime - loop->start_hrtime, (unsigned long long)loop->loop_cnt, loop->nactives, loop->nios, loop->ntimers,
          loop->nidles);
}

static void eventFDReadCB(wio_t* io, sbuf_t* buf) {
    wloop_t* loop = io->loop;
    wevent_t* pev = NULL;
    wevent_t ev;
    uint64_t count = sbufGetBufLength(buf);
#if defined(OS_UNIX) && HAVE_EVENTFD
    assert(sbufGetBufLength(buf) == sizeof(count));
    sbufReadUnAlignedUI64(buf, &count);
#endif
    (void)count;
    for (uint64_t i = 0; i < count; ++i) {
        mutexLock(&loop->custom_events_mutex);
        if (event_queue_empty(&loop->custom_events)) {
            goto unlock;
        }
        pev = event_queue_front(&loop->custom_events);
        if (pev == NULL) {
            goto unlock;
        }
        ev = *pev;
        event_queue_pop_front(&loop->custom_events);
        // NOTE: unlock before cb, avoid deadlock if wloopPostEvent called in cb.
        mutexUnlock(&loop->custom_events_mutex);
        if (ev.cb) {
            ev.cb(&ev);
        }
    }
    bufferpoolResuesBuffer(io->loop->bufpool, buf);
    return;
unlock:
    mutexUnlock(&loop->custom_events_mutex);
    bufferpoolResuesBuffer(io->loop->bufpool, buf);
}

static int wloopCreateEventFDS(wloop_t* loop) {
#if defined(OS_UNIX) && HAVE_EVENTFD
    int efd = eventfd(0, 0);
    if (efd < 0) {
        wloge("eventfd create failed!");
        return -1;
    }
    loop->eventfds[0] = loop->eventfds[1] = efd;
#elif defined(OS_UNIX) && HAVE_PIPE
    if (pipe(loop->eventfds) != 0) {
        wloge("pipe create failed!");
        return -1;
    }
#else
    if (createSocketPair(AF_INET, SOCK_STREAM, 0, loop->eventfds) != 0) {
        wloge("socketpair create failed!");
        return -1;
    }
#endif
    wio_t* io = wRead(loop, loop->eventfds[EVENTFDS_READ_INDEX], eventFDReadCB);
    io->priority = WEVENT_HIGH_PRIORITY;
    ++loop->intern_nevents;
    return 0;
}

static void wloopDestroyEventFDS(wloop_t* loop) {
#if defined(OS_UNIX) && HAVE_EVENTFD
    // NOTE: eventfd has only one fd
    SAFE_CLOSE(loop->eventfds[0]);
#elif defined(OS_UNIX) && HAVE_PIPE
    SAFE_CLOSE(loop->eventfds[0]);
    SAFE_CLOSE(loop->eventfds[1]);
#else
    // NOTE: Avoid duplication closesocket in wio_cleanup
    // SAFE_CLOSESOCKET(loop->eventfds[EVENTFDS_READ_INDEX]);
    SAFE_CLOSESOCKET(loop->eventfds[EVENTFDS_WRITE_INDEX]);
#endif
    loop->eventfds[0] = loop->eventfds[1] = -1;
}

void wloopPostEvent(wloop_t* loop, wevent_t* ev) {
    if (ev->loop == NULL) {
        ev->loop = loop;
    }
    if (ev->event_type == 0) {
        ev->event_type = WEVENT_TYPE_CUSTOM;
    }
    if (ev->event_id == 0) {
        ev->event_id = wloopGetNextEventID();
    }

    int nwrite = 0;
    mutexLock(&loop->custom_events_mutex);
    if (loop->eventfds[EVENTFDS_WRITE_INDEX] == -1) {
        if (wloopCreateEventFDS(loop) != 0) {
            goto unlock;
        }
    }
#if defined(OS_UNIX) && HAVE_EVENTFD
    uint64_t count = 1;
    nwrite = write(loop->eventfds[EVENTFDS_WRITE_INDEX], &count, sizeof(count));
#elif defined(OS_UNIX) && HAVE_PIPE
    nwrite = write(loop->eventfds[EVENTFDS_WRITE_INDEX], "e", 1);
#else
    nwrite = send(loop->eventfds[EVENTFDS_WRITE_INDEX], "e", 1, 0);
#endif
    if (nwrite <= 0) {
        wloge("wloopPostEvent failed!");
        goto unlock;
    }
    if (loop->custom_events.maxsize == 0) {
        event_queue_init(&loop->custom_events, CUSTOM_EVENT_QUEUE_INIT_SIZE);
    }
    event_queue_push_back(&loop->custom_events, ev);
unlock:
    mutexUnlock(&loop->custom_events_mutex);
}

static void wloopInit(wloop_t* loop) {
#ifdef OS_WIN
    WSAInit();
#endif
#ifdef SIGPIPE
    // NOTE: if not ignore SIGPIPE, write twice when peer close will lead to exit process by SIGPIPE.
    signal(SIGPIPE, SIG_IGN);
#endif

    loop->status = WLOOP_STATUS_STOP;
    loop->pid = getTID();
    // loop->tid = getTID();  tid is taken at wloop_create

    // idles
    list_init(&loop->idles);

    // timers
    heap_init(&loop->timers, timersCompare);
    heap_init(&loop->realtimers, timersCompare);

    // ios
    // NOTE: io_array_init when wioGet -> io_array_resize
    // io_array_init(&loop->ios, IO_ARRAY_INIT_SIZE);

    // NOTE: iowatcherInit when wioAdd -> iowatcherAddEvent
    // iowatcherInit(loop);

    // custom_events
    mutexInit(&loop->custom_events_mutex);
    // NOTE: wloopCreateEventFDS when wloopPostEvent or wloopRun
    loop->eventfds[0] = loop->eventfds[1] = -1;

    // NOTE: init start_time here, because wtimerAdd use it.
    loop->start_ms = getTimeOfDayMS();
    loop->start_hrtime = loop->cur_hrtime = getHRTimeUs();
}

static void wloopCleanup(wloop_t* loop) {
    // pendings
    printd("cleanup pendings...\n");
    for (int i = 0; i < WEVENT_PRIORITY_SIZE; ++i) {
        loop->pendings[i] = NULL;
    }

    // ios
    printd("cleanup ios...\n");
    for (size_t i = 0; i < loop->ios.maxsize; ++i) {
        wio_t* io = loop->ios.ptr[i];
        if (io) {
            wioFree(io);
        }
    }
    io_array_cleanup(&loop->ios);

    // idles
    printd("cleanup idles...\n");
    struct list_node* node = loop->idles.next;
    widle_t* idle;
    while (node != &loop->idles) {
        idle = IDLE_ENTRY(node);
        node = node->next;
        EVENTLOOP_FREE(idle);
    }
    list_init(&loop->idles);

    // timers
    printd("cleanup timers...\n");
    wtimer_t* timer;
    while (loop->timers.root) {
        timer = TIMER_ENTRY(loop->timers.root);
        heap_dequeue(&loop->timers);
        EVENTLOOP_FREE(timer);
    }
    heap_init(&loop->timers, NULL);
    while (loop->realtimers.root) {
        timer = TIMER_ENTRY(loop->realtimers.root);
        heap_dequeue(&loop->realtimers);
        EVENTLOOP_FREE(timer);
    }
    heap_init(&loop->realtimers, NULL);

    // iowatcher
    iowatcherCleanUp(loop);

    // custom_events
    mutexLock(&loop->custom_events_mutex);
    wloopDestroyEventFDS(loop);
    event_queue_cleanup(&loop->custom_events);
    mutexUnlock(&loop->custom_events_mutex);
    mutexDestroy(&loop->custom_events_mutex);
}

wloop_t* wloopCreate(int flags, buffer_pool_t* swimmingpool, long tid) {
    wloop_t* loop;
    EVENTLOOP_ALLOC_SIZEOF(loop);
    wloopInit(loop);
    loop->flags |= flags;
    loop->bufpool = swimmingpool;
    loop->tid = tid;
    // wlogd("wloopCreate tid=%ld", loop->tid);
    return loop;
}

void wloopDestroy(wloop_t** pp) {
    if (pp == NULL || *pp == NULL) return;
    wloop_t* loop = *pp;
    if (loop->status == WLOOP_STATUS_DESTROY) return;
    loop->status = WLOOP_STATUS_DESTROY;
    wlogd("wloopDestroy tid=%ld", loop->tid);
    wloopCleanup(loop);
    EVENTLOOP_FREE(loop);
    *pp = NULL;
}

#ifdef DEBUG
_Thread_local wtimer_t* _loop_debug_timer = NULL;
#endif

// while (loop->status) { wloopProcessEvents(loop); }
int wloopRun(wloop_t* loop) {
    if (loop == NULL) return -1;
    if (loop->status == WLOOP_STATUS_RUNNING) return -2;

    loop->status = WLOOP_STATUS_RUNNING;
    loop->pid = getTID();
    // loop->tid = getTID();  tid is taken at wloop_create
    // wlogd("wloopRun tid=%ld", loop->tid);

    if (loop->intern_nevents == 0) {
        mutexLock(&loop->custom_events_mutex);
        if (loop->eventfds[EVENTFDS_WRITE_INDEX] == -1) {
            wloopCreateEventFDS(loop);
        }
        mutexUnlock(&loop->custom_events_mutex);

#ifdef DEBUG
        _loop_debug_timer = wtimerAdd(loop, wloopStatTimerCallBack, WLOOP_STAT_TIMEOUT, INFINITE);
        ++loop->intern_nevents;
#endif
    }

    while (loop->status != WLOOP_STATUS_STOP) {
        if (loop->status == WLOOP_STATUS_PAUSE) {
            hv_msleep(WLOOP_PAUSE_TIME);
            wloopUpdateTime(loop);
            continue;
        }
        ++loop->loop_cnt;
        if ((loop->flags & WLOOP_FLAG_QUIT_WHEN_NO_ACTIVE_EVENTS) && loop->nactives <= loop->intern_nevents) {
            break;
        }
        wloopProcessEvents(loop, WLOOP_MAX_BLOCK_TIME);
        if (loop->flags & WLOOP_FLAG_RUN_ONCE) {
            break;
        }
    }

    loop->status = WLOOP_STATUS_STOP;
    loop->end_hrtime = getHRTimeUs();

    if (loop->flags & WLOOP_FLAG_AUTO_FREE) {
        wloopDestroy(&loop);
    }
    return 0;
}

int wloopWakeup(wloop_t* loop) {
    wevent_t ev;
    memorySet(&ev, 0, sizeof(ev));
    wloopPostEvent(loop, &ev);
    return 0;
}

int wloopStop(wloop_t* loop) {
    if (loop == NULL) return -1;
    if (loop->status == WLOOP_STATUS_STOP) return -2;
    wlogd("wloopStop tid=%ld", getTID());
    if (getTID() != loop->tid) {
        wloopWakeup(loop);
    }
    loop->status = WLOOP_STATUS_STOP;
    return 0;
}

int wloopPause(wloop_t* loop) {
    if (loop->status == WLOOP_STATUS_RUNNING) {
        loop->status = WLOOP_STATUS_PAUSE;
    }
    return 0;
}

int wloopResume(wloop_t* loop) {
    if (loop->status == WLOOP_STATUS_PAUSE) {
        loop->status = WLOOP_STATUS_RUNNING;
    }
    return 0;
}

wloop_status_e wloopStatus(wloop_t* loop) {
    return loop->status;
}

void wloopUpdateTime(wloop_t* loop) {
    loop->cur_hrtime = getHRTimeUs();
    if ((time_t)wloopNow(loop) != time(NULL)) {
        // systemtime changed, we adjust start_ms
        loop->start_ms = getTimeOfDayMS() - (loop->cur_hrtime - loop->start_hrtime) / 1000;
    }
}

uint64_t wloopNow(wloop_t* loop) {
    return loop->start_ms / 1000 + (loop->cur_hrtime - loop->start_hrtime) / 1000000;
}

uint64_t wloopNowMS(wloop_t* loop) {
    return loop->start_ms + (loop->cur_hrtime - loop->start_hrtime) / 1000;
}

uint64_t wloopNowUS(wloop_t* loop) {
    return loop->start_ms * 1000 + (loop->cur_hrtime - loop->start_hrtime);
}

uint64_t wloopNowLoopRunTime(wloop_t* loop) {
    return loop->cur_hrtime;
}

uint64_t wioGetLastReadTime(wio_t* io) {
    wloop_t* loop = io->loop;
    return loop->start_ms + (io->last_read_hrtime - loop->start_hrtime) / 1000;
}

uint64_t wioGetLastWriteTime(wio_t* io) {
    wloop_t* loop = io->loop;
    return loop->start_ms + (io->last_write_hrtime - loop->start_hrtime) / 1000;
}

long wloopPID(wloop_t* loop) {
    return loop->pid;
}

long wloopTID(wloop_t* loop) {
    return loop->tid;
}

uint64_t wloopCount(wloop_t* loop) {
    return loop->loop_cnt;
}

uint32_t wloopNIOS(wloop_t* loop) {
    return loop->nios;
}

uint32_t wloopNTimers(wloop_t* loop) {
    return loop->ntimers;
}

uint32_t wloopNIdles(wloop_t* loop) {
    return loop->nidles;
}

uint32_t wloopNActives(wloop_t* loop) {
    return loop->nactives;
}

buffer_pool_t* wloopGetBufferPool(wloop_t* loop) {
    return loop->bufpool;
}

void wloopSetUserData(wloop_t* loop, void* userdata) {
    loop->userdata = userdata;
}

void* wloopGetUserData(wloop_t* loop) {
    return loop->userdata;
}

widle_t* widleAdd(wloop_t* loop, widle_cb cb, uint32_t repeat) {
    widle_t* idle;
    EVENTLOOP_ALLOC_SIZEOF(idle);
    idle->event_type = WEVENT_TYPE_IDLE;
    idle->priority = WEVENT_LOWEST_PRIORITY;
    idle->repeat = repeat;
    list_add(&idle->node, &loop->idles);
    EVENT_ADD(loop, idle, cb);
    loop->nidles++;
    return idle;
}

static void __widle_del(widle_t* idle) {
    if (idle->destroy) return;
    idle->destroy = 1;
    list_del(&idle->node);
    idle->loop->nidles--;
}

void widleDelete(widle_t* idle) {
    if (!idle->active) return;
    __widle_del(idle);
    EVENT_DEL(idle);
}

wtimer_t* wtimerAdd(wloop_t* loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat) {
    if (timeout_ms == 0) return NULL;
    htimeout_t* timer;
    EVENTLOOP_ALLOC_SIZEOF(timer);
    timer->event_type = WEVENT_TYPE_TIMEOUT;
    timer->priority = WEVENT_HIGHEST_PRIORITY;
    timer->repeat = repeat;
    timer->timeout = timeout_ms;
    wloopUpdateTime(loop);
    timer->next_timeout = loop->cur_hrtime + (uint64_t)timeout_ms * 1000;
    // NOTE: Limit granularity to 100ms
    if (timeout_ms >= 1000 && timeout_ms % 100 == 0) {
        timer->next_timeout = timer->next_timeout / 100000 * 100000;
    }
    heap_insert(&loop->timers, &timer->node);
    EVENT_ADD(loop, timer, cb);
    loop->ntimers++;
    return (wtimer_t*)timer;
}

void wtimerReset(wtimer_t* timer, uint32_t timeout_ms) {
    if (timer->event_type != WEVENT_TYPE_TIMEOUT) {
        return;
    }
    wloop_t* loop = timer->loop;
    htimeout_t* timeout = (htimeout_t*)timer;
    if (timer->destroy) {
        loop->ntimers++;
    }
    else {
        heap_remove(&loop->timers, &timer->node);
    }
    if (timer->repeat == 0) {
        timer->repeat = 1;
    }
    if (timeout_ms > 0) {
        timeout->timeout = timeout_ms;
    }
    timer->next_timeout = loop->cur_hrtime + (uint64_t)timeout->timeout * 1000;
    // NOTE: Limit granularity to 100ms
    if (timeout->timeout >= 1000 && timeout->timeout % 100 == 0) {
        timer->next_timeout = timer->next_timeout / 100000 * 100000;
    }
    heap_insert(&loop->timers, &timer->node);
    EVENT_RESET(timer);
}

wtimer_t* wtimerAddPeriod(wloop_t* loop, wtimer_cb cb, int8_t minute, int8_t hour, int8_t day, int8_t week, int8_t month, uint32_t repeat) {
    if (minute > 59 || hour > 23 || day > 31 || week > 6 || month > 12) {
        return NULL;
    }
    hperiod_t* timer;
    EVENTLOOP_ALLOC_SIZEOF(timer);
    timer->event_type = WEVENT_TYPE_PERIOD;
    timer->priority = WEVENT_HIGH_PRIORITY;
    timer->repeat = repeat;
    timer->minute = minute;
    timer->hour = hour;
    timer->day = day;
    timer->month = month;
    timer->week = week;
    timer->next_timeout = (uint64_t)cronNextTimeout(minute, hour, day, week, month) * 1000000;
    heap_insert(&loop->realtimers, &timer->node);
    EVENT_ADD(loop, timer, cb);
    loop->ntimers++;
    return (wtimer_t*)timer;
}

static void __wtimer_del(wtimer_t* timer) {
    if (timer->destroy) return;
    if (timer->event_type == WEVENT_TYPE_TIMEOUT) {
        heap_remove(&timer->loop->timers, &timer->node);
    }
    else if (timer->event_type == WEVENT_TYPE_PERIOD) {
        heap_remove(&timer->loop->realtimers, &timer->node);
    }
    timer->loop->ntimers--;
    timer->destroy = 1;
}

void wtimerDelete(wtimer_t* timer) {
    if (!timer->active) return;
    __wtimer_del(timer);
    EVENT_DEL(timer);
}

const char* wioGetEngine(void) {
#ifdef EVENT_SELECT
    return "select";
#elif defined(EVENT_POLL)
    return "poll";
#elif defined(EVENT_EPOLL)
    return "epoll";
#elif defined(EVENT_KQUEUE)
    return "kqueue";
#elif defined(EVENT_IOCP)
    return "iocp";
#elif defined(EVENT_PORT)
    return "evport";
#else
    return "noevent";
#endif
}

static inline wio_t* __wio_get(wloop_t* loop, int fd) {
    if (fd >= (int)loop->ios.maxsize) {
        int newsize = ceil2e(fd);
        newsize = max(newsize, IO_ARRAY_INIT_SIZE);
        io_array_resize(&loop->ios, newsize > fd ? newsize : 2 * fd);
    }
    return loop->ios.ptr[fd];
}

wio_t* wioGet(wloop_t* loop, int fd) {
    wio_t* io = __wio_get(loop, fd);
    if (io == NULL) {
        EVENTLOOP_ALLOC_SIZEOF(io);
        wioInit(io);
        io->event_type = WEVENT_TYPE_IO;
        io->loop = loop;
        io->fd = fd;
        loop->ios.ptr[fd] = io;
    }

    if (!io->ready) {
        wioReady(io);
    }

    return io;
}

void wioDetach(wio_t* io) {
    wloop_t* loop = io->loop;
    int fd = io->fd;
    assert(loop != NULL && fd < (int)loop->ios.maxsize);
    loop->ios.ptr[fd] = NULL;
}

void wioAttach(wloop_t* loop, wio_t* io) {
    int fd = io->fd;
    // NOTE: wio was not freed for reused when closed, but attached wio can't be reused,
    // so we need to free it if fd exists to avoid memory leak.
    wio_t* preio = __wio_get(loop, fd);
    if (preio != NULL && preio != io) {
        assert(preio->closed);
        wioFree(preio);
    }

    io->loop = loop;
    loop->ios.ptr[fd] = io;
}

bool wioExists(wloop_t* loop, int fd) {
    if (fd >= (int)loop->ios.maxsize) {
        return false;
    }
    return loop->ios.ptr[fd] != NULL;
}

int wioAdd(wio_t* io, wio_cb cb, int events) {
    printd("wioAdd fd=%d io->events=%d events=%d\n", io->fd, io->events, events);
#ifdef OS_WIN
    // Windows iowatcher not work on stdio
    if (io->fd < 3) return -1;
#endif
    wloop_t* loop = io->loop;
    if (!io->active) {
        EVENT_ADD(loop, io, cb);
        loop->nios++;
    }

    if (!io->ready) {
        wioReady(io);
    }

    if (cb) {
        io->cb = (wevent_cb)cb;
    }

    if (!(io->events & events)) {
        iowatcherAddEvent(loop, io->fd, events);
        io->events |= events;
    }
    return 0;
}

int wioDel(wio_t* io, int events) {
    printd("wioDel fd=%d io->events=%d events=%d\n", io->fd, io->events, events);
#ifdef OS_WIN
    // Windows iowatcher not work on stdio
    if (io->fd < 3) return -1;
#endif
    if (!io->active) return -1;

    if (io->events & events) {
        iowatcherDelEvent(io->loop, io->fd, events);
        io->events &= ~events;
    }
    if (io->events == 0) {
        io->loop->nios--;
        // NOTE: not EVENT_DEL, avoid free
        EVENT_INACTIVE(io);
    }
    return 0;
}

static void wio_close_event_cb(wevent_t* ev) {
    wio_t* io = (wio_t*)ev->userdata;
    uint32_t id = (uintptr_t)ev->privdata;
    if (io->id != id) return;
    wioClose(io);
}

int wioCloseAsync(wio_t* io) {
    wevent_t ev;
    memorySet(&ev, 0, sizeof(ev));
    ev.cb = wio_close_event_cb;
    ev.userdata = io;
    ev.privdata = (void*)(uintptr_t)io->id;
    wloopPostEvent(io->loop, &ev);
    return 0;
}

//------------------high-level apis-------------------------------------------
wio_t* wRead(wloop_t* loop, int fd, wread_cb read_cb) {
    wio_t* io = wioGet(loop, fd);
    assert(io != NULL);
    if (read_cb) {
        io->read_cb = read_cb;
    }
    wioRead(io);
    return io;
}

wio_t* wWrite(wloop_t* loop, int fd, sbuf_t* buf, wwrite_cb write_cb) {
    wio_t* io = wioGet(loop, fd);
    assert(io != NULL);
    if (write_cb) {
        io->write_cb = write_cb;
    }
    wioWrite(io, buf);
    return io;
}

wio_t* waccept(wloop_t* loop, int listenfd, waccept_cb accept_cb) {
    wio_t* io = wioGet(loop, listenfd);
    assert(io != NULL);
    if (accept_cb) {
        io->accept_cb = accept_cb;
    }
    if (wioAccept(io) != 0) return NULL;
    return io;
}

wio_t* wconnect(wloop_t* loop, int connfd, wconnect_cb connect_cb) {
    wio_t* io = wioGet(loop, connfd);
    assert(io != NULL);
    if (connect_cb) {
        io->connect_cb = connect_cb;
    }
    if (wioConnect(io) != 0) return NULL;
    return io;
}

void wClose(wloop_t* loop, int fd) {
    wio_t* io = wioGet(loop, fd);
    assert(io != NULL);
    wioClose(io);
}

wio_t* wRecv(wloop_t* loop, int connfd, wread_cb read_cb) {
    // wio_t* io = wioGet(loop, connfd);
    // assert(io != NULL);
    // io->recv = 1;
    // if (io->io_type != WIO_TYPE_SSL) {
    // io->io_type = WIO_TYPE_TCP;
    //}
    return wRead(loop, connfd, read_cb);
}

wio_t* wSend(wloop_t* loop, int connfd, sbuf_t* buf, wwrite_cb write_cb) {
    // wio_t* io = wioGet(loop, connfd);
    // assert(io != NULL);
    // io->send = 1;
    // if (io->io_type != WIO_TYPE_SSL) {
    // io->io_type = WIO_TYPE_TCP;
    //}
    return wWrite(loop, connfd, buf, write_cb);
}

wio_t* wRecvFrom(wloop_t* loop, int sockfd, wread_cb read_cb) {
    // wio_t* io = wioGet(loop, sockfd);
    // assert(io != NULL);
    // io->recvfrom = 1;
    // io->io_type = WIO_TYPE_UDP;
    return wRead(loop, sockfd, read_cb);
}

wio_t* wSendTo(wloop_t* loop, int sockfd, sbuf_t* buf, wwrite_cb write_cb) {
    // wio_t* io = wioGet(loop, sockfd);
    // assert(io != NULL);
    // io->sendto = 1;
    // io->io_type = WIO_TYPE_UDP;
    return wWrite(loop, sockfd, buf, write_cb);
}

//-----------------top-level apis---------------------------------------------
wio_t* wioCreateSocket(wloop_t* loop, const char* host, int port, wio_type_e type, wio_side_e side) {
    int sock_type = (type & WIO_TYPE_SOCK_STREAM) ? SOCK_STREAM : (type & WIO_TYPE_SOCK_DGRAM) ? SOCK_DGRAM : (type & WIO_TYPE_SOCK_RAW) ? SOCK_RAW : -1;
    if (sock_type == -1) return NULL;
    sockaddr_u addr;
    memorySet(&addr, 0, sizeof(addr));
    int ret = -1;
#ifdef ENABLE_UDS
    if (port < 0) {
        sockaddr_set_path(&addr, host);
        ret = 0;
    }
#endif
    if (port >= 0) {
        ret = sockaddrSetIpPort(&addr, host, port);
    }
    if (ret != 0) {
        // printError("unknown host: %s\n", host);
        return NULL;
    }
    int sockfd = socket(addr.sa.sa_family, sock_type, 0);
    if (sockfd < 0) {
        printError("socket");
        return NULL;
    }
    wio_t* io = NULL;
    if (side == WIO_SERVER_SIDE) {
#ifdef OS_UNIX
        so_reuseaddr(sockfd, 1);
        // so_reuseport(sockfd, 1);
#endif
        if (addr.sa.sa_family == AF_INET6) {
            ipV6Only(sockfd, 0);
        }
        if (bind(sockfd, &addr.sa, sockaddrLen(&addr)) < 0) {
            printError("bind");
            closesocket(sockfd);
            return NULL;
        }
        if (sock_type == SOCK_STREAM) {
            if (listen(sockfd, SOMAXCONN) < 0) {
                printError("listen");
                closesocket(sockfd);
                return NULL;
            }
        }
    }
    io = wioGet(loop, sockfd);
    assert(io != NULL);
    io->io_type = type;
    if (side == WIO_SERVER_SIDE) {
        wioSetLocaladdr(io, &addr.sa, sockaddrLen(&addr));
        io->priority = WEVENT_HIGH_PRIORITY;
    }
    else {
        wioSetPeerAddr(io, &addr.sa, sockaddrLen(&addr));
    }
    return io;
}

wio_t* wloopCreateTcpServer(wloop_t* loop, const char* host, int port, waccept_cb accept_cb) {
    wio_t* io = wioCreateSocket(loop, host, port, WIO_TYPE_TCP, WIO_SERVER_SIDE);
    if (io == NULL) return NULL;
    wioSetCallBackAccept(io, accept_cb);
    if (wioAccept(io) != 0) return NULL;
    return io;
}

wio_t* wloopCreateTcpClient(wloop_t* loop, const char* host, int port, wconnect_cb connect_cb, wclose_cb close_cb) {
    wio_t* io = wioCreateSocket(loop, host, port, WIO_TYPE_TCP, WIO_CLIENT_SIDE);
    if (io == NULL) return NULL;
    wioSetCallBackConnect(io, connect_cb);
    wioSetCallBackClose(io, close_cb);
    if (wioConnect(io) != 0) return NULL;
    return io;
}

wio_t* wloopCreateUdpServer(wloop_t* loop, const char* host, int port) {
    return wioCreateSocket(loop, host, port, WIO_TYPE_UDP, WIO_SERVER_SIDE);
}

wio_t* wloopCreateUdpClient(wloop_t* loop, const char* host, int port) {
    return wioCreateSocket(loop, host, port, WIO_TYPE_UDP, WIO_CLIENT_SIDE);
}
