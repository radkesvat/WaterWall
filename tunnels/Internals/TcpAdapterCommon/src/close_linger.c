#include "TcpAdapterCommon/close_linger.h"

#include "loggers/network_logger.h"

#ifdef OS_LINUX
typedef struct tcp_adapter_linger_s
{
    wio_t              *io;
    local_idle_table_t *table;
    local_idle_item_t  *idle;
    uint64_t            deadline_ms;
} tcp_adapter_linger_t;

enum
{
    kCloseLingerIdleMs  = 5000,
    kCloseLingerTotalMs = 30000
};

static void onLingerClose(wio_t *io)
{
    tcp_adapter_linger_t *linger = weventGetUserdata(io);
    weventSetUserData(io, NULL);
    wioSetCallBackRead(io, NULL);
    wioSetCallBackWrite(io, NULL);
    wioSetCallBackClose(io, NULL);
    local_idle_item_t *idle = linger->idle;
    linger->idle            = NULL;
    if (idle != NULL)
    {
        bool removed = localidletableRemoveIdleItem(linger->table, idle);
        if (! removed)
        {
            LOGF("TcpAdapterCommon: failed to remove closing socket idle item");
            abortProgramNow(1);
        }
    }
    memoryFree(linger);
}

static void onLingerExpire(local_idle_item_t *item)
{
    tcp_adapter_linger_t *linger = item->userdata;
    item->userdata               = NULL;
    linger->idle                 = NULL;
    // Stop and expiry discard any pending output without extending the deadline.
    wioFree(linger->io);
}

static void onLingerRead(wio_t *io, sbuf_t *buf)
{
    tcp_adapter_linger_t *linger = weventGetUserdata(io);
    bufferpoolReuseBuffer(wloopGetBufferPool(weventGetLoop(io)), buf);
    if (linger->deadline_ms == 0)
        return;

    const uint64_t now = wloopNowMonotonicMS(weventGetLoop(io));
    if (now >= linger->deadline_ms)
    {
        wioFree(io);
        return;
    }
    localidletableKeepIdleItemForAtleast(
        linger->table, linger->idle, min((uint64_t) kCloseLingerIdleMs, linger->deadline_ms - now));
}

static void onLingerWriteComplete(wio_t *io)
{
    if (! wioCheckWriteComplete(io))
        return;

    wioSetCallBackWrite(io, NULL);
    if (shutdown(wioGetFD(io), SHUT_WR) != 0)
    {
        wioClose(io);
        return;
    }

    tcp_adapter_linger_t *linger = weventGetUserdata(io);
    local_idle_item_t    *idle   = linger->idle;
    linger->idle                 = NULL;
    bool removed                 = localidletableRemoveIdleItem(linger->table, idle);
    if (! removed)
    {
        LOGF("TcpAdapterCommon: failed to replace draining socket idle item");
        abortProgramNow(1);
    }
    const uint64_t now  = wloopNowMonotonicMS(weventGetLoop(io));
    linger->deadline_ms = now + kCloseLingerTotalMs;
    linger->idle =
        localidletableCreateItem(linger->table, (hash_t) wioGetID(io), linger, onLingerExpire, kCloseLingerIdleMs);
    if (linger->idle == NULL)
    {
        LOGF("TcpAdapterCommon: duplicate half-closed socket idle item");
        abortProgramNow(1);
    }
}
#endif

bool tcpAdapterBeginCloseLinger(wio_t *io, local_idle_table_t *table)
{
    assert(io != NULL && table != NULL);
#ifdef OS_LINUX
    if (! wloopNormalDispatchAllowed(weventGetLoop(io)) || wioIsClosed(io) || wioGetError(io) != 0)
        return false;

    // The socket owns no line reference and remains in the worker's drain inventory.
    tcp_adapter_linger_t *linger = memoryAllocateZero(sizeof(*linger));
    linger->io                   = io;
    linger->table                = table;
    linger->idle                 = localidletableCreateItem(
        linger->table, (hash_t) wioGetID(io), linger, onLingerExpire, WIO_DEFAULT_CLOSE_TIMEOUT);
    if (linger->idle == NULL)
    {
        LOGF("TcpAdapterCommon: duplicate draining socket idle item");
        abortProgramNow(1);
    }
    weventSetUserData(io, linger);
    wioSetCallBackConnect(io, NULL);
    wioSetCallBackRead(io, onLingerRead);
    wioSetCallBackClose(io, onLingerClose);
    wioSetCallBackWrite(io, onLingerWriteComplete);
    wioDisableSplice(io);
    if (wioRead(io) == 0)
        onLingerWriteComplete(io);
    return true;
#else
    discard table;
    discard io;
    return false;
#endif
}
