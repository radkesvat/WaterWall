#include "packet_affinity.h"

#include "devices/device_flow_affinity.h"
#include "devices/device_frag_affinity.h"
#include "ipv4_packet_view.h"
#include "loggers/internal_logger.h"
#include "packet_tunnel.h"
#include "worker_messages.h"

struct packet_affinity_s
{
    tunnel_t                     *tunnel;
    LineTaskFnWithBuf             continuation;
    device_frag_affinity_table_t *fragments;
};

typedef struct packet_affinity_message_s
{
    tunnel_t         *tunnel;
    line_t           *line;
    LineTaskFnWithBuf continuation;
    sbuf_t           *buf;
    bool              recalculate_checksum;
} packet_affinity_message_t;

static void packetAffinityRun(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard                    arg2;
    discard                    arg3;
    packet_affinity_message_t *message = arg1;
    assert(worker->wid == lineGetWID(message->line));
    if (lineIsAlive(message->line))
    {
        lineSetRecalculateChecksum(message->line, message->recalculate_checksum);
        message->continuation(message->tunnel, message->line, message->buf);
        if (! lineIsAlive(message->line))
        {
            LOGF("PacketAffinity: continuation destroyed its worker packet line");
            abortProgramNow(1);
        }
    }
    else
        bufferpoolReuseBuffer(worker->buffer_pool, message->buf);
    lineUnref(message->line);
    memoryFree(message);
}

static void packetAffinityCancel(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard                    arg2;
    discard                    arg3;
    discard                    reason;
    packet_affinity_message_t *message = arg1;
    /* Cancellation can run after owner pools are gone, on any thread. */
    sbufDestroy(message->buf);
    lineUnref(message->line);
    memoryFree(message);
}

packet_affinity_t *packetAffinityCreate(tunnel_t *tunnel, LineTaskFnWithBuf continuation)
{
    assert(tunnel != NULL && continuation != NULL);
    packet_affinity_t *affinity = memoryAllocateZero(sizeof(*affinity));
    affinity->tunnel            = tunnel;
    affinity->continuation      = continuation;
    if (getWorkersCount() > 1)
    {
        affinity->fragments = deviceFragAffinityCreateShared(kDeviceFragmentPreserve, 0);
        if (affinity->fragments == NULL)
        {
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
    deviceFragAffinityDestroy(affinity->fragments);
    memoryFree(affinity);
}

static void packetAffinityPublish(packet_affinity_t *affinity, line_t *source_line, sbuf_t *buf, wid_t wid,
                                  bool recalculate_checksum)
{
    line_t *target = tunnelchainGetWorkerPacketLine(tunnelGetChain(affinity->tunnel), wid);
    assert(target != NULL);
    if (wid == lineGetWID(source_line))
    {
        lineRef(target);
        lineSetRecalculateChecksum(target, recalculate_checksum);
        affinity->continuation(affinity->tunnel, target, buf);
        if (! lineIsAlive(target))
        {
            LOGF("PacketAffinity: continuation destroyed its worker packet line");
            abortProgramNow(1);
        }
        lineUnref(target);
        return;
    }
    packet_affinity_message_t *message = memoryAllocate(sizeof(*message));
    *message                           = (packet_affinity_message_t) {.tunnel               = affinity->tunnel,
                                                                      .line                 = target,
                                                                      .continuation         = affinity->continuation,
                                                                      .buf                  = buf,
                                                                      .recalculate_checksum = recalculate_checksum};
    lineRef(target);
    sendWorkerMessageForceQueueBestEffortWithCleanup(
        wid, (WorkerMessageCallback) packetAffinityRun, packetAffinityCancel, message, NULL, NULL);
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

    bool requested = packettunnelTakeChecksumRequest(source_line);
    if (packet.fragmented)
    {
        /* A staged buffer must not inherit another packet's line metadata when
         * it is eventually released. Fragment checksum repair changes only IP. */
        if (requested && ! packettunnelFinalizeChecksumRequest(true, sbufGetMutablePtr(buf), sbufGetLength(buf)))
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
            packetAffinityPublish(affinity, source_line, fragment.released[i], fragment.wid, false);
        packetAffinityPublish(affinity, source_line, buf, fragment.wid, false);
        return;
    }
    wid_t      wid;
    const bool identified = deviceFlowAffineWID(sbufGetRawPtr(buf), sbufGetLength(buf), &wid);
    assert(identified);
    discard identified;
    packetAffinityPublish(affinity, source_line, buf, wid, requested);
}
