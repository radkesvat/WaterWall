#include "GnsCommon/port.h"

#include "GnsCommon/engine.h"

#include "loggers/network_logger.h"

struct gns_port_s
{
    wmutex_t             lock;
    uint32_t             references; /* the owner, plus one per wake that is on its way; under lock */
    gns_port_datagram_t *head;
    gns_port_datagram_t *tail;
    uint32_t             count;
    uint32_t             limit;
    uint32_t             incoming; /* the connection that the accept callback admitted; 0 when none waits */
    uint64_t             refused;
    bool                 dirty;        /* something arrived since the owner last took */
    bool                 driving;      /* the owner is between Enter and a successful Leave */
    bool                 wake_pending; /* a wake is on its way to the owner */
    bool                 detached;
    wid_t                owner;
    int64_t              token;
    gns_port_wake_fn     wake;
    void                *user;
};

/* Tokens name ports to the accept callback, which can run on any worker and after its session has ended. A slot's
 * generation changes whenever its port leaves, so an old token resolves to nothing. */
static struct
{
    wmutex_t     lock;
    gns_port_t **ports;
    uint32_t    *generations;
    uint32_t    *free_slots; /* stack of the slots that hold no port */
    uint32_t     free_count;
    uint32_t     capacity;
    uint32_t     users; /* nodes that hold the runtime; changed only where nodes are created and destroyed */
} g_ports;

static void portUnref(gns_port_t *port)
{
    mutexLock(&port->lock);
    assert(port->references > 0);
    const uint32_t left = --port->references;
    mutexUnlock(&port->lock);
    if (left == 0)
    {
        assert(port->detached && port->head == NULL);
        mutexDestroy(&port->lock);
        memoryFree(port);
    }
}

static void portWakeOnWorker(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard     worker;
    discard     arg2;
    discard     arg3;
    gns_port_t *port = arg1;
    mutexLock(&port->lock);
    port->wake_pending  = false;
    const bool detached = port->detached;
    mutexUnlock(&port->lock);
    if (! detached)
    {
        port->wake(port->user);
    }
    portUnref(port);
}

static void portWakeCancelled(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard     arg2;
    discard     arg3;
    discard     reason;
    gns_port_t *port = arg1;
    /* The worker is stopping. Its sessions are aborted by their node; nothing has to be delivered. */
    mutexLock(&port->lock);
    port->wake_pending = false;
    mutexUnlock(&port->lock);
    portUnref(port);
}

/* With the port lock held: records an arrival and says whether a wake has to be posted for it. The caller posts it
 * after releasing the lock; the reference for the wake is taken here. */
static bool portArrivedLocked(gns_port_t *port)
{
    port->dirty = true;
    if (port->driving || port->wake_pending)
    {
        return false;
    }
    port->wake_pending = true;
    ++port->references;
    return true;
}

static void portPostWake(gns_port_t *port)
{
    /* Accepted work runs portWakeOnWorker or, when the worker is going away, portWakeCancelled; a refusal runs the
     * cancellation before this returns. Either way the reference is released exactly once. */
    const worker_message_submit_result_e result = sendWorkerMessageForceQueueWithCleanup(
        port->owner, (WorkerMessageCallback) portWakeOnWorker, portWakeCancelled, port, NULL, NULL);
    discard result;
}

gns_port_t *gnsPortCreate(wid_t owner, uint32_t queue_limit, gns_port_wake_fn wake, void *user)
{
    assert(wake != NULL && queue_limit > 0);
    gns_port_t *port = memoryAllocateZero(sizeof(*port));
    mutexInit(&port->lock);
    port->references = 1;
    port->limit      = queue_limit;
    port->owner      = owner;
    port->wake       = wake;
    port->user       = user;

    mutexLock(&g_ports.lock);
    if (g_ports.free_count == 0)
    {
        const uint32_t capacity = g_ports.capacity == 0 ? 64U : g_ports.capacity * 2U;
        g_ports.ports           = memoryReAllocate(g_ports.ports, sizeof(*g_ports.ports) * capacity);
        g_ports.generations     = memoryReAllocate(g_ports.generations, sizeof(*g_ports.generations) * capacity);
        g_ports.free_slots      = memoryReAllocate(g_ports.free_slots, sizeof(*g_ports.free_slots) * capacity);
        for (uint32_t slot = capacity; slot > g_ports.capacity; --slot)
        {
            g_ports.ports[slot - 1]                  = NULL;
            g_ports.generations[slot - 1]            = 1;
            g_ports.free_slots[g_ports.free_count++] = slot - 1;
        }
        g_ports.capacity = capacity;
    }
    const uint32_t slot = g_ports.free_slots[--g_ports.free_count];
    g_ports.ports[slot] = port;
    port->token         = (int64_t) (((uint64_t) g_ports.generations[slot] << 32) | slot);
    mutexUnlock(&g_ports.lock);
    return port;
}

void gnsPortRelease(gns_port_t *port)
{
    assert(port->detached);
    portUnref(port);
}

int64_t gnsPortToken(const gns_port_t *port)
{
    return port->token;
}

bool gnsPortSend(void *user, const uint8_t *data, size_t length, const gns_external_addr_t *to)
{
    discard     to;
    gns_port_t *port = user;
    mutexLock(&port->lock);
    if (port->detached)
    {
        mutexUnlock(&port->lock);
        return true; /* the session is gone and so is its wire */
    }
    if (port->count >= port->limit)
    {
        ++port->refused;
        mutexUnlock(&port->lock);
        return false;
    }
    gns_port_datagram_t *datagram = memoryAllocate(sizeof(*datagram) + length);
    datagram->next                = NULL;
    datagram->length              = (uint32_t) length;
    memoryCopy(datagram->bytes, data, length);
    if (port->tail != NULL)
    {
        port->tail->next = datagram;
    }
    else
    {
        port->head = datagram;
    }
    port->tail = datagram;
    ++port->count;
    const bool wake = portArrivedLocked(port);
    mutexUnlock(&port->lock);
    if (wake)
    {
        portPostWake(port);
    }
    return true;
}

/* The engine's accept callback. A carrier has one session, so a second connection on the same port is refused. */
static bool portAdmit(int64_t token, uint32_t connection)
{
    const uint32_t slot       = (uint32_t) ((uint64_t) token & UINT32_MAX);
    const uint32_t generation = (uint32_t) ((uint64_t) token >> 32);
    gns_port_t    *port       = NULL;
    mutexLock(&g_ports.lock);
    if (slot < g_ports.capacity && g_ports.generations[slot] == generation && g_ports.ports[slot] != NULL)
    {
        port = g_ports.ports[slot];
        mutexLock(&port->lock);
        ++port->references;
        mutexUnlock(&port->lock);
    }
    mutexUnlock(&g_ports.lock);
    if (port == NULL)
    {
        return false;
    }
    bool admitted = false;
    bool wake     = false;
    mutexLock(&port->lock);
    if (! port->detached && port->incoming == 0)
    {
        port->incoming = connection;
        admitted       = true;
        wake           = portArrivedLocked(port);
    }
    mutexUnlock(&port->lock);
    if (wake)
    {
        portPostWake(port);
    }
    portUnref(port);
    return admitted;
}

void gnsPortEnter(gns_port_t *port)
{
    mutexLock(&port->lock);
    port->driving = true;
    mutexUnlock(&port->lock);
}

gns_port_datagram_t *gnsPortTake(gns_port_t *port, uint32_t *incoming)
{
    mutexLock(&port->lock);
    gns_port_datagram_t *list = port->head;
    port->head = port->tail = NULL;
    port->count             = 0;
    port->dirty             = false;
    *incoming               = port->incoming;
    mutexUnlock(&port->lock);
    return list;
}

bool gnsPortLeave(gns_port_t *port)
{
    mutexLock(&port->lock);
    const bool settled = ! port->dirty;
    if (settled)
    {
        port->driving = false;
    }
    mutexUnlock(&port->lock);
    return settled;
}

void gnsPortYield(gns_port_t *port)
{
    bool wake = false;
    mutexLock(&port->lock);
    port->driving = false;
    if (port->dirty && ! port->detached)
    {
        wake = portArrivedLocked(port);
    }
    mutexUnlock(&port->lock);
    if (wake)
    {
        portPostWake(port);
    }
}

void gnsPortDatagramFree(gns_port_datagram_t *datagram)
{
    memoryFree(datagram);
}

void gnsPortDetach(gns_port_t *port)
{
    mutexLock(&port->lock);
    assert(! port->detached);
    port->detached            = true;
    gns_port_datagram_t *list = port->head;
    port->head = port->tail = NULL;
    port->count             = 0;
    mutexUnlock(&port->lock);
    while (list != NULL)
    {
        gns_port_datagram_t *next = list->next;
        memoryFree(list);
        list = next;
    }
    const uint32_t slot = (uint32_t) ((uint64_t) port->token & UINT32_MAX);
    mutexLock(&g_ports.lock);
    assert(slot < g_ports.capacity && g_ports.ports[slot] == port);
    g_ports.ports[slot] = NULL;
    ++g_ports.generations[slot];
    g_ports.free_slots[g_ports.free_count++] = slot;
    mutexUnlock(&g_ports.lock);
}

uint64_t gnsPortRefusedDatagrams(gns_port_t *port)
{
    mutexLock(&port->lock);
    const uint64_t refused = port->refused;
    mutexUnlock(&port->lock);
    return refused;
}

static void runtimeLog(gns_engine_log_t level, const char *text)
{
    if (level == kGnsEngineLogError)
    {
        LOGE("GNS: %s", text);
    }
    else if (level == kGnsEngineLogWarning)
    {
        LOGW("GNS: %s", text);
    }
    else
    {
        LOGD("GNS: %s", text);
    }
}

bool gnsRuntimeAcquire(const char *node_type)
{
    if (g_ports.users == 0)
    {
        mutexInit(&g_ports.lock);
    }
    char error[1024];
    if (! gnsEngineAcquire(runtimeLog, portAdmit, error, sizeof(error)))
    {
        LOGF("%s: GameNetworkingSockets did not start: %s", node_type, error);
        if (g_ports.users == 0)
        {
            mutexDestroy(&g_ports.lock);
        }
        return false;
    }
    ++g_ports.users;
    return true;
}

void gnsRuntimeRelease(void)
{
    assert(g_ports.users > 0);
    gnsEngineRelease();
    if (--g_ports.users == 0)
    {
        for (uint32_t slot = 0; slot < g_ports.capacity; ++slot)
        {
            if (UNLIKELY(g_ports.ports[slot] != NULL))
            {
                LOGF("GnsCommon: a port is still registered when the runtime stops");
                abortProgramNow(1);
            }
        }
        memoryFree(g_ports.ports);
        memoryFree(g_ports.generations);
        memoryFree(g_ports.free_slots);
        g_ports.ports       = NULL;
        g_ports.generations = NULL;
        g_ports.free_slots  = NULL;
        g_ports.free_count  = 0;
        g_ports.capacity    = 0;
        mutexDestroy(&g_ports.lock);
    }
}
