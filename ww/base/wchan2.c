#define _GNU_SOURCE
#undef __STRICT_ANSI__

#ifdef __APPLE__
#define _XOPEN_SOURCE
#endif

#include "wlibc.h"
// #include <errno.h>

// #include <stdlib.h>
// #include <stdio.h>
// #include <string.h>
// #include <unistd.h>

// #include <time.h>
// #include <sys/time.h>

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#endif

#include "chan_queue.h"
#include "wchan.h"

#ifdef _WIN32
#include <windows.h>
#define CLOCK_REALTIME 0
static int clock_gettime(int __attribute__((__unused__)) clockid, struct timespec *tp)
{
    FILETIME       ft;
    ULARGE_INTEGER t64;
    GetSystemTimeAsFileTime(&ft);
    t64.LowPart  = ft.dwLowDateTime;
    t64.HighPart = ft.dwHighDateTime;
    tp->tv_sec   = t64.QuadPart / 10000000 - 11644473600;
    tp->tv_nsec  = t64.QuadPart % 10000000 * 100;
    return 0;
}
#endif

static int bufferedChanOpen(wchan_t *chan, size_t capacity);
static int bufferedWchanSend(wchan_t *chan, void *data);
static int bufferedWchanRecv(wchan_t *chan, void **data);

static int unbufferedChanOpen(wchan_t *chan);
static int unbufferedWchanSend(wchan_t *chan, void *data);
static int unbufferedWchanRecv(wchan_t *chan, void **data);

static int chanCanRecv(wchan_t *chan);
static int chanCanSend(wchan_t *chan);
static int chanIsBuffered(wchan_t *chan);

static void currentUtcTime(struct timespec *ts)
{
#ifdef __MACH__
    clock_serv_t    cclock;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
    clock_get_time(cclock, &mts);
    mach_port_deallocate(mach_task_self(), cclock);
    ts->tv_sec  = mts.tv_sec;
    ts->tv_nsec = mts.tv_nsec;
#else
    clock_gettime(CLOCK_REALTIME, ts);
#endif
}

// Allocates and returns a new channel.
wchan_t *chanInit(size_t capacity)
{
    wchan_t *chan = (wchan_t *) memoryAllocate(sizeof(wchan_t));
    if (! chan)
    {
        errno = ENOMEM;
        return NULL;
    }

    if (capacity > 0)
    {
        if (bufferedChanOpen(chan, capacity) != 0)
        {
            memoryFree(chan);
            return NULL;
        }
    }
    else
    {
        if (unbufferedChanOpen(chan) != 0)
        {
            memoryFree(chan);
            return NULL;
        }
    }

    return chan;
}

static int bufferedChanOpen(wchan_t *chan, size_t capacity)
{
    queue_t *queue = queue_init(capacity);
    if (! queue)
        return -1;

    if (unbufferedChanOpen(chan) != 0)
    {
        queue_dispose(queue);
        return -1;
    }

    chan->queue = queue;
    return 0;
}

static int unbufferedChanOpen(wchan_t *chan)
{
    mutexInit(&chan->w_mu);

    mutexInit(&chan->r_mu);

    mutexInit(&chan->m_mu);

    condvarInit(&chan->r_cond);
    condvarInit(&chan->w_cond);
  

    chan->closed    = 0;
    chan->r_waiting = 0;
    chan->w_waiting = 0;
    chan->queue     = NULL;
    chan->data      = NULL;
    return 0;
}

// Releases the channel resources.
void chanDispose(wchan_t *chan)
{
    if (chanIsBuffered(chan))
    {
        queue_dispose(chan->queue);
    }

    mutexDestroy(&chan->w_mu);
    mutexDestroy(&chan->r_mu);
    mutexDestroy(&chan->m_mu);
    contvarDestroy(&chan->r_cond);
    contvarDestroy(&chan->w_cond);
    memoryFree(chan);
}

int chanClose(wchan_t *chan)
{
    int success = 0;
    mutexLock(&chan->m_mu);
    if (chan->closed)
    {
        success = -1;
        errno   = EPIPE;
    }
    else
    {
        chan->closed = 1;
        pthread_cond_broadcast(&chan->r_cond);
        pthread_cond_broadcast(&chan->w_cond);
    }
    mutexUnlock(&chan->m_mu);
    return success;
}

int chanIsClosed(wchan_t *chan)
{
    mutexLock(&chan->m_mu);
    int closed = chan->closed;
    mutexUnlock(&chan->m_mu);
    return closed;
}

int chanSend(wchan_t *chan, void *data)
{
    if (chanIsClosed(chan))
    {
        errno = EPIPE;
        return -1;
    }

    return chanIsBuffered(chan) ? bufferedWchanSend(chan, data) : unbufferedWchanSend(chan, data);
}

int chanRecv(wchan_t *chan, void **data)
{
    return chanIsBuffered(chan) ? bufferedWchanRecv(chan, data) : unbufferedWchanRecv(chan, data);
}

static int bufferedWchanSend(wchan_t *chan, void *data)
{
    mutexLock(&chan->m_mu);
    while (chan->queue->size == chan->queue->capacity)
    {
        chan->w_waiting++;
        condvarWait(&chan->w_cond, &chan->m_mu);
        chan->w_waiting--;
    }

    int success = queue_add(chan->queue, data);

    if (chan->r_waiting > 0)
    {
        pthread_cond_signal(&chan->r_cond);
    }

    mutexUnlock(&chan->m_mu);
    return success;
}

static int bufferedWchanRecv(wchan_t *chan, void **data)
{
    mutexLock(&chan->m_mu);
    while (chan->queue->size == 0)
    {
        if (chan->closed)
        {
            mutexUnlock(&chan->m_mu);
            errno = EPIPE;
            return -1;
        }
        chan->r_waiting++;
        condvarWait(&chan->r_cond, &chan->m_mu);
        chan->r_waiting--;
    }

    void *msg = queue_remove(chan->queue);
    if (data)
        *data = msg;

    if (chan->w_waiting > 0)
    {
        pthread_cond_signal(&chan->w_cond);
    }

    mutexUnlock(&chan->m_mu);
    return 0;
}

static int unbufferedWchanSend(wchan_t *chan, void *data)
{
    mutexLock(&chan->w_mu);
    mutexLock(&chan->m_mu);

    if (chan->closed)
    {
        mutexUnlock(&chan->m_mu);
        mutexUnlock(&chan->w_mu);
        errno = EPIPE;
        return -1;
    }

    chan->data = data;
    chan->w_waiting++;
    if (chan->r_waiting > 0)
    {
        pthread_cond_signal(&chan->r_cond);
    }
    condvarWait(&chan->w_cond, &chan->m_mu);

    mutexUnlock(&chan->m_mu);
    mutexUnlock(&chan->w_mu);
    return 0;
}

static int unbufferedWchanRecv(wchan_t *chan, void **data)
{
    mutexLock(&chan->r_mu);
    mutexLock(&chan->m_mu);

    while (! chan->closed && ! chan->w_waiting)
    {
        chan->r_waiting++;
        condvarWait(&chan->r_cond, &chan->m_mu);
        chan->r_waiting--;
    }

    if (chan->closed)
    {
        mutexUnlock(&chan->m_mu);
        mutexUnlock(&chan->r_mu);
        errno = EPIPE;
        return -1;
    }

    if (data)
        *data = chan->data;
    chan->w_waiting--;
    pthread_cond_signal(&chan->w_cond);

    mutexUnlock(&chan->m_mu);
    mutexUnlock(&chan->r_mu);
    return 0;
}

int chanSize(wchan_t *chan)
{
    int size = 0;
    if (chanIsBuffered(chan))
    {
        mutexLock(&chan->m_mu);
        size = chan->queue->size;
        mutexUnlock(&chan->m_mu);
    }
    return size;
}

typedef struct
{
    int      recv;
    wchan_t *chan;
    void    *msg_in;
    int      index;
} select_op_t;

int chanSelect(wchan_t *recvChans[], int recvCount, void **recvOut, wchan_t *sendChans[], int sendCount,
                void *sendMsgs[])
{
    select_op_t candidates[recvCount + sendCount];
    int         count = 0;

    for (int i = 0; i < recvCount; i++)
    {
        if (chanCanRecv(recvChans[i]))
        {
            candidates[count++] = (select_op_t) {1, recvChans[i], NULL, i};
        }
    }

    for (int i = 0; i < sendCount; i++)
    {
        if (chanCanSend(sendChans[i]))
        {
            candidates[count++] = (select_op_t) {0, sendChans[i], sendMsgs[i], i + recvCount};
        }
    }

    if (count == 0)
        return -1;

    struct timespec ts;
    currentUtcTime(&ts);
    srand(ts.tv_nsec);

    select_op_t selected = candidates[rand() % count];
    if (selected.recv)
    {
        if (chanRecv(selected.chan, recvOut) != 0)
            return -1;
    }
    else
    {
        if (chanSend(selected.chan, selected.msg_in) != 0)
            return -1;
    }

    return selected.index;
}

static int chanCanRecv(wchan_t *chan)
{
    if (chanIsBuffered(chan))
    {
        return chanSize(chan) > 0;
    }
    mutexLock(&chan->m_mu);
    int sender = chan->w_waiting > 0;
    mutexUnlock(&chan->m_mu);
    return sender;
}

static int chanCanSend(wchan_t *chan)
{
    int send;
    mutexLock(&chan->m_mu);
    send = chanIsBuffered(chan) ? (chan->queue->size < chan->queue->capacity) : (chan->r_waiting > 0);
    mutexUnlock(&chan->m_mu);
    return send;
}

static int chanIsBuffered(wchan_t *chan)
{
    return chan->queue != NULL;
}

// Typed send/receive wrappers

int chanSendInt32(wchan_t *chan, int32_t data)
{
    int32_t *wrapped = memoryAllocate(sizeof(int32_t));
    if (! wrapped)
        return -1;
    *wrapped = data;

    int success = chanSend(chan, wrapped);
    if (success != 0)
        memoryFree(wrapped);
    return success;
}

int chanRecvInt32(wchan_t *chan, int32_t *data)
{
    int32_t *wrapped = NULL;
    int      success = chanRecv(chan, (void **) &wrapped);
    if (wrapped)
    {
        *data = *wrapped;
        memoryFree(wrapped);
    }
    return success;
}

int chanSendInt64(wchan_t *chan, int64_t data)
{
    int64_t *wrapped = memoryAllocate(sizeof(int64_t));
    if (! wrapped)
        return -1;
    *wrapped = data;

    int success = chanSend(chan, wrapped);
    if (success != 0)
        memoryFree(wrapped);
    return success;
}

int chanRecvInt64(wchan_t *chan, int64_t *data)
{
    int64_t *wrapped = NULL;
    int      success = chanRecv(chan, (void **) &wrapped);
    if (wrapped)
    {
        *data = *wrapped;
        memoryFree(wrapped);
    }
    return success;
}

int chanSendDouble(wchan_t *chan, double data)
{
    double *wrapped = memoryAllocate(sizeof(double));
    if (! wrapped)
        return -1;
    *wrapped = data;

    int success = chanSend(chan, wrapped);
    if (success != 0)
        memoryFree(wrapped);
    return success;
}

int chanRecvDouble(wchan_t *chan, double *data)
{
    double *wrapped = NULL;
    int     success = chanRecv(chan, (void **) &wrapped);
    if (wrapped)
    {
        *data = *wrapped;
        memoryFree(wrapped);
    }
    return success;
}

int chanSendBuf(wchan_t *chan, void *data, size_t size)
{
    void *wrapped = memoryAllocate(size);
    if (! wrapped)
        return -1;
    memcpy(wrapped, data, size);

    int success = chanSend(chan, wrapped);
    if (success != 0)
        memoryFree(wrapped);
    return success;
}

int chanRecvBuf(wchan_t *chan, void *data, size_t size)
{
    void *wrapped = NULL;
    int   success = chanRecv(chan, &wrapped);
    if (wrapped)
    {
        memcpy(data, wrapped, size);
        memoryFree(wrapped);
    }
    return success;
}
