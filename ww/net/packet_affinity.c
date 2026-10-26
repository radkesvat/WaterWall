#include "packet_affinity.h"

#include "devices/device_flow_affinity.h"
#include "devices/device_frag_affinity.h"
#include "ipv4_packet_view.h"
#include "loggers/internal_logger.h"
#include "objects/node.h"
#include "packet_batch.h"
#include "packet_tunnel.h"
#include "worker_messages.h"

enum
{
    /* Shared across every destination of one continuation, including the active
     * packet until its callback returns. Fragment staging has its own budget. */
    kPacketAffinityPacketLimit   = 512,
    kPacketAffinityChargeLimit   = 8 * 1024 * 1024,
    kPacketAffinityPacketQuantum = 256,
    kPacketAffinityByteQuantum   = 256 * 1024
};

typedef struct packet_affinity_record_s
{
    struct packet_affinity_record_s *next;
    sbuf_t                          *buf;
    size_t                           charge;
} packet_affinity_record_t;

typedef struct packet_affinity_queue_s
{
    packet_affinity_t        *affinity;
    packet_affinity_record_t *head;
    packet_affinity_record_t *tail;
    line_t                   *line;
    wid_t                     wid;
    bool                      scheduled;
    bool                      closed;
} packet_affinity_queue_t;

struct packet_affinity_s
{
    tunnel_t                     *tunnel;
    LineTaskFnWithBuf             continuation;
    device_frag_affinity_table_t *fragments;
    /* Short admission/dequeue critical sections only; never call out or post
     * while locked. This also linearizes the aggregate allocation budget. */
    wmutex_t                lock;
    size_t                  charge;
    unsigned                packets;
    unsigned                workers;
    packet_affinity_queue_t queues[];
};

static void packetAffinityRun(void *worker, void *arg1, void *arg2, void *arg3);

static void packetAffinityReleaseRecord(packet_affinity_t *affinity, packet_affinity_record_t *record)
{
    mutexLock(&affinity->lock);
    assert(affinity->packets > 0 && affinity->charge >= record->charge);
    --affinity->packets;
    affinity->charge -= record->charge;
    mutexUnlock(&affinity->lock);
    memoryFree(record);
}

static void packetAffinityCancel(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard                  arg2;
    discard                  arg3;
    discard                  reason;
    packet_affinity_queue_t *queue    = arg1;
    packet_affinity_t       *affinity = queue->affinity;
    mutexLock(&affinity->lock);
    packet_affinity_record_t *record = queue->head;
    line_t                   *line   = queue->line;
    queue->head                      = NULL;
    queue->tail                      = NULL;
    queue->line                      = NULL;
    queue->scheduled                 = false;
    mutexUnlock(&affinity->lock);
    /* Task-XOR-cancel owns the token's line reference. Cancellation can run
     * synchronously or on an unregistered teardown thread, without pools. */
    while (record != NULL)
    {
        packet_affinity_record_t *next = record->next;
        sbufDestroy(record->buf);
        packetAffinityReleaseRecord(affinity, record);
        record = next;
    }
    lineUnref(line);
}

static void packetAffinitySchedule(packet_affinity_queue_t *queue)
{
    /* Capacity/closed-admission refusal is lossy packet delivery. Cleanup
     * consumes the complete accepted FIFO, including synchronous rejection. */
    const worker_message_submit_result_e result =
        sendWorkerMessageForceQueueWithCleanup(queue->wid, packetAffinityRun, packetAffinityCancel, queue, NULL, NULL);
    discard result;
}

static void packetAffinityDrain(worker_t *worker, packet_affinity_queue_t *queue, bool queued)
{
    packet_affinity_t *affinity = queue->affinity;
    line_t            *line     = queue->line;
    assert(worker->wid == queue->wid && lineIsOnCurrentWorker(line));
    unsigned       packets = 0;
    size_t         bytes   = 0;
    packet_batch_t batch;
    /* Synchronous delivery inherits the reader/decoder's existing batch.
     * Deferred drains form their own scope; packet scopes may never nest. */
    if (queued)
        packetBatchBegin(&batch);
    while (packets < kPacketAffinityPacketQuantum && bytes < kPacketAffinityByteQuantum)
    {
        if (! wloopNormalDispatchAllowed(worker->loop))
            break;
        mutexLock(&affinity->lock);
        packet_affinity_record_t *record = queue->head;
        if (record != NULL)
        {
            queue->head = record->next;
            if (queue->head == NULL)
                queue->tail = NULL;
        }
        mutexUnlock(&affinity->lock);
        if (record == NULL)
            break;
        ++packets;
        bytes += sbufGetLength(record->buf);
        if (lineIsAlive(line))
        {
            affinity->continuation(affinity->tunnel, line, record->buf);
            if (! lineIsAlive(line))
            {
                LOGF("PacketAffinity: continuation destroyed its worker packet line");
                abortProgramNow(1);
            }
        }
        else
            bufferpoolReuseBuffer(worker->buffer_pool, record->buf);
        packetAffinityReleaseRecord(affinity, record);
    }
    /* Keep the token claimed through batch flushing, because a participant's
     * flush can synchronously submit more packets to this continuation. */
    if (queued)
        packetBatchEnd(&batch);
    mutexLock(&affinity->lock);
    const bool more = queue->head != NULL;
    if (! more)
    {
        queue->scheduled = false;
        queue->line      = NULL;
    }
    mutexUnlock(&affinity->lock);
    if (more)
        packetAffinitySchedule(queue);
    else
        lineUnref(line);
}

static void packetAffinityRun(void *worker, void *arg1, void *arg2, void *arg3)
{
    discard arg2;
    discard arg3;
    packetAffinityDrain(worker, arg1, true);
}

packet_affinity_t *packetAffinityCreate(tunnel_t *tunnel, LineTaskFnWithBuf continuation)
{
    assert(tunnel != NULL && continuation != NULL);
    const unsigned     workers  = getWorkersCount();
    packet_affinity_t *affinity = memoryAllocateZero(sizeof(*affinity) + workers * sizeof(affinity->queues[0]));
    affinity->tunnel            = tunnel;
    affinity->continuation      = continuation;
    affinity->workers           = workers;
    if (! mutexTryInit(&affinity->lock))
    {
        memoryFree(affinity);
        return NULL;
    }
    for (unsigned wid = 0; wid < workers; ++wid)
    {
        affinity->queues[wid].affinity = affinity;
        affinity->queues[wid].wid      = (wid_t) wid;
    }
    if (workers > 1)
    {
        affinity->fragments = deviceFragAffinityCreateShared(kDeviceFragmentPreserve, 0);
        if (affinity->fragments == NULL)
        {
            mutexDestroy(&affinity->lock);
            memoryFree(affinity);
            return NULL;
        }
    }
    return affinity;
}

void packetAffinityDestroy(packet_affinity_t *affinity)
{
    if (affinity == NULL)
        return;
    /* Runtime quiescence settles every token before nodes are destroyed. The
     * caller also excludes new producers; a mutex alone cannot grant lifetime. */
    for (unsigned wid = 0; wid < affinity->workers; ++wid)
    {
        if (affinity->queues[wid].scheduled)
        {
            LOGF("PacketAffinity: destroyed before queued callbacks settled");
            abortProgramNow(1);
        }
    }
    assert(affinity->packets == 0 && affinity->charge == 0);
    deviceFragAffinityDestroy(affinity->fragments);
    mutexDestroy(&affinity->lock);
    memoryFree(affinity);
}

static void packetAffinityPublish(packet_affinity_t *affinity, line_t *source_line, sbuf_t *buf, wid_t wid)
{
    assert(wid < affinity->workers);
    packet_affinity_queue_t *queue  = &affinity->queues[wid];
    const size_t             charge = sbufGetAllocationCharge(buf) + sizeof(packet_affinity_record_t);
    mutexLock(&affinity->lock);
    if (queue->closed || affinity->packets == kPacketAffinityPacketLimit ||
        charge > kPacketAffinityChargeLimit - affinity->charge)
    {
        mutexUnlock(&affinity->lock);
        lineReuseBuffer(source_line, buf);
        return;
    }
    packet_affinity_record_t *record = memoryAllocate(sizeof(*record));
    *record                          = (packet_affinity_record_t) {.buf = buf, .charge = charge};
    if (queue->tail != NULL)
        queue->tail->next = record;
    else
        queue->head = record;
    queue->tail = record;
    ++affinity->packets;
    affinity->charge += charge;
    const bool schedule = ! queue->scheduled;
    if (schedule)
    {
        queue->line = tunnelchainGetWorkerPacketLine(tunnelGetChain(affinity->tunnel), wid);
        assert(queue->line != NULL);
        lineRef(queue->line);
        queue->scheduled = true;
    }
    mutexUnlock(&affinity->lock);
    if (! schedule)
        return;
    worker_t *worker = getCurrentWorker();
    if (wid == lineGetWID(source_line) && wloopCurrentThreadInNormalCallback(worker->loop))
        packetAffinityDrain(worker, queue, false);
    else
        packetAffinitySchedule(queue);
}

void packetAffinityForward(packet_affinity_t *affinity, line_t *source_line, sbuf_t *buf)
{
    assert(affinity != NULL && source_line != NULL && buf != NULL && lineIsOnCurrentWorker(source_line));
    ipv4_packet_view_t packet;
    if (getWorkersCount() <= 1 || ! tunnelchainIsWorkerPacketLine(tunnelGetChain(affinity->tunnel), source_line) ||
        ! ipv4packetviewParse(sbufGetRawPtr(buf), sbufGetLength(buf), &packet) ||
        packet.ip_total_length != sbufGetLength(buf) || (packet.protocol != 6 && packet.protocol != 17))
    {
        affinity->continuation(affinity->tunnel, source_line, buf);
        return;
    }

    if (packet.fragmented)
    {
        /* Settle repair before staging; fragment repair changes only IP. */
        if (! packettunnelConsumeChecksumRequest(buf))
        {
            lineReuseBuffer(source_line, buf);
            return;
        }
        device_frag_affinity_result_t       fragment;
        const device_frag_affinity_action_t action =
            deviceFragAffinityOffer(affinity->fragments, sbufGetRawPtr(buf), sbufGetLength(buf), buf, &fragment);
        if (action == kDeviceFragAffinityConsumedDrop || action == kDeviceFragAffinityStaged)
            return;
        assert(action == kDeviceFragAffinityDispatch);
        for (unsigned i = 0; i < fragment.released_count; ++i)
            packetAffinityPublish(affinity, source_line, fragment.released[i], fragment.wid);
        packetAffinityPublish(affinity, source_line, buf, fragment.wid);
        return;
    }
    wid_t      wid;
    const bool identified = deviceFlowAffineWID(sbufGetRawPtr(buf), sbufGetLength(buf), &wid);
    assert(identified);
    discard identified;
    packetAffinityPublish(affinity, source_line, buf, wid);
}

/* A private chain helper owns only its dispatcher and metadata. It creates no
 * normal lines, pairs no lines, and advertises no checksum-trust capability. */
typedef struct flow_affinity_tunnel_state_s
{
    node_t             node;
    packet_affinity_t *affinity;
} flow_affinity_tunnel_state_t;

static void flowAffinityTunnelPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    flow_affinity_tunnel_state_t *state = tunnelGetState(t);
    if (tunnelchainIsWorkerPacketLine(tunnelGetChain(t), line))
    {
        mutexLock(&state->affinity->lock);
        const bool closed = state->affinity->queues[lineGetWID(line)].closed;
        mutexUnlock(&state->affinity->lock);
        if (closed)
        {
            lineReuseBuffer(line, buf);
            return;
        }
    }
    packetAffinityForward(state->affinity, line, buf);
}

static void flowAffinityTunnelClose(tunnel_t *t, line_t *line)
{
    if (! tunnelchainIsWorkerPacketLine(tunnelGetChain(t), line))
        return;
    flow_affinity_tunnel_state_t *state    = tunnelGetState(t);
    packet_affinity_t            *affinity = state->affinity;
    packet_affinity_queue_t      *queue    = &affinity->queues[lineGetWID(line)];
    mutexLock(&affinity->lock);
    queue->closed                    = true;
    packet_affinity_record_t *record = queue->head;
    queue->head                      = NULL;
    queue->tail                      = NULL;
    mutexUnlock(&affinity->lock);
    /* Keep an already-published token and its line reference for its eventual
     * task-or-cancel settlement. An executing continuation owns its buffer. */
    while (record != NULL)
    {
        packet_affinity_record_t *next = record->next;
        lineReuseBuffer(line, record->buf);
        packetAffinityReleaseRecord(affinity, record);
        record = next;
    }
}

static void flowAffinityTunnelFinishUp(tunnel_t *t, line_t *line)
{
    flowAffinityTunnelClose(t, line);
    tunnelNextUpStreamFinish(t, line);
}

static void flowAffinityTunnelFinishDown(tunnel_t *t, line_t *line)
{
    flowAffinityTunnelClose(t, line);
    tunnelPrevDownStreamFinish(t, line);
}

static void flowAffinityTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                       context;
    flow_affinity_tunnel_state_t *state = tunnelGetState(t);
    packetAffinityDestroy(state->affinity);
    tunnelDestroy(t);
}

tunnel_t *flowAffinityTunnelCreate(flow_affinity_direction_t direction)
{
    assert(direction == kFlowAffinityUpstream || direction == kFlowAffinityDownstream);
    tunnel_t *t = packettunnelCreate(NULL, sizeof(flow_affinity_tunnel_state_t), 0);
    if (t == NULL)
        return NULL;
    flow_affinity_tunnel_state_t *state       = tunnelGetState(t);
    static char                   type_name[] = "FlowAffinity";
    state->node                               = (node_t) {.name                  = type_name,
                                                          .type                  = type_name,
                                                          .hash_type             = calcHashBytes("FlowAffinity", sizeof("FlowAffinity") - 1),
                                                          .layer_group           = kNodeLayer3,
                                                          .layer_group_prev_node = kNodeLayer3,
                                                          .layer_group_next_node = kNodeLayer3,
                                                          .can_have_prev         = true,
                                                          .can_have_next         = true};
    t->node                                   = &state->node;
    state->node.instance                      = t;
    state->affinity                           = packetAffinityCreate(
        t, direction == kFlowAffinityUpstream ? tunnelNextUpStreamPayload : tunnelPrevDownStreamPayload);
    if (state->affinity == NULL)
    {
        tunnelDestroy(t);
        return NULL;
    }
    t->fnPayloadU = direction == kFlowAffinityUpstream ? flowAffinityTunnelPayload : tunnelNextUpStreamPayload;
    t->fnPayloadD = direction == kFlowAffinityDownstream ? flowAffinityTunnelPayload : tunnelPrevDownStreamPayload;
    t->fnFinU     = flowAffinityTunnelFinishUp;
    t->fnFinD     = flowAffinityTunnelFinishDown;
    t->onDestroy  = flowAffinityTunnelDestroy;
    return t;
}
