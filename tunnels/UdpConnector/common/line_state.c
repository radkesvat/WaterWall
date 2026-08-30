#include "structure.h"

#include "loggers/network_logger.h"

bool udpconnectorLinestateInitialize(udpconnector_lstate_t *ls, tunnel_t *t, line_t *l)
{
    *ls = (udpconnector_lstate_t) {
        .tunnel                           = t,
        .line                             = l,
        .idle_handle                      = NULL,
        .line_idle_id                     = 0,
        .fixed_binding                    = NULL,
        .peer_bindings                    = udpconnector_peer_binding_map_init(),
        .bindings_head                    = NULL,
        .bindings_count                   = 0,
        .last_send_binding                = NULL,
        .packet_dns_requests              = NULL,
        .packet_destinations              = NULL,
        .packet_destinations_count        = 0,
        .packet_initial_destination_index = 0,
        .pause_queue                      = bufferqueueCreate(kUdpPauseQueueCapacity),
        .established                      = false,
        .read_paused                      = false,
        .write_paused                     = false,
        .queue_pause_sent                 = false,
        .route_destination_pinned         = false,
    };

    udpconnector_tstate_t *ts = tunnelGetState(t);
    if (ts->balance_mode == kUdpConnectorBalanceModePacket)
    {
        uint32_t count = ts->destinations_count > 0 ? ts->destinations_count : 1;

        size_t packet_destinations_size;
        if (! memoryTryComputeArraySize((size_t) count, sizeof(*ls->packet_destinations), &packet_destinations_size))
        {
            LOGE("UdpConnector: packet destination cache size is not representable");
            return false;
        }

        ls->packet_destinations = memoryAllocateZero(packet_destinations_size);
        if (UNLIKELY(ls->packet_destinations == NULL))
        {
            LOGE("UdpConnector: failed to allocate packet destination cache");
            return false;
        }

        ls->packet_destinations_count = count;
        for (uint32_t i = 0; i < count; ++i)
        {
            ls->packet_destinations[i].pending_queue = bufferqueueCreate(kUdpPauseQueueCapacity);
        }
    }

    return true;
}

void udpconnectorCancelPacketDnsRequests(udpconnector_lstate_t *ls)
{
    udpconnector_packet_dns_request_t *request = ls->packet_dns_requests;

    while (request != NULL)
    {
        udpconnector_packet_dns_request_t *next = request->next;
        request->cancelled                      = true;
        request->prev                           = NULL;
        request->next                           = NULL;
        request                                 = next;
    }

    ls->packet_dns_requests = NULL;
}

static void udpconnectorPacketDestinationCachesDestroy(udpconnector_lstate_t *ls)
{
    if (ls->packet_destinations != NULL)
    {
        for (uint32_t i = 0; i < ls->packet_destinations_count; ++i)
        {
            addresscontextReset(&ls->packet_destinations[i].dest_ctx);
            bufferqueueDestroy(&ls->packet_destinations[i].pending_queue);
        }

        memoryFree(ls->packet_destinations);
        ls->packet_destinations       = NULL;
        ls->packet_destinations_count = 0;
    }

    addresscontextReset(&ls->packet_base_dest_ctx);
}

void udpconnectorLinestateDestroy(udpconnector_lstate_t *ls)
{
    if (UNLIKELY(ls->idle_handle != NULL || ls->fixed_binding != NULL || ls->last_send_binding != NULL ||
                 ls->bindings_head != NULL || ls->bindings_count != 0 ||
                 udpconnector_peer_binding_map_size(&ls->peer_bindings) != 0))
    {
        LOGF("UdpConnector: line state still owns an idle item or peer binding during destruction");
        abortProgramNow(1);
    }

    udpconnectorCancelPacketDnsRequests(ls);
    udpconnectorPacketDestinationCachesDestroy(ls);
    bufferqueueDestroy(&ls->pause_queue);
    udpconnector_peer_binding_map_drop(&ls->peer_bindings);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(udpconnector_lstate_t)));
}
