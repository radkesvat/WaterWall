#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorLinestateInitialize(udpconnector_lstate_t *ls, tunnel_t *t, line_t *l, wio_t *io)
{
    *ls = (udpconnector_lstate_t){
        .tunnel                           = t,
        .line                             = l,
        .io                               = io,
        .dns_request                      = NULL,
        .packet_dns_requests              = NULL,
        .packet_destinations              = NULL,
        .packet_destinations_count        = 0,
        .packet_initial_destination_index = 0,
        .pause_queue                      = bufferqueueCreate(kUdpPauseQueueCapacity),
        .established                      = false,
        .read_paused                      = false,
        .resolving                        = false,
        .write_paused                     = false,
        .queue_pause_sent                 = false,
    };

    udpconnector_tstate_t *ts = tunnelGetState(t);
    if (ts->balance_mode == kUdpConnectorBalanceModePacket)
    {
        uint32_t count = ts->destinations_count > 0 ? ts->destinations_count : 1;

        ls->packet_destinations       = memoryAllocateZero(sizeof(*ls->packet_destinations) * (size_t) count);
        ls->packet_destinations_count = count;
        for (uint32_t i = 0; i < count; ++i)
        {
            ls->packet_destinations[i].pending_queue = bufferqueueCreate(kUdpPauseQueueCapacity);
        }
    }

    if (io != NULL)
    {
        weventSetUserData(io, ls);
    }
}

void udpconnectorCancelDnsRequest(udpconnector_lstate_t *ls)
{
    if (ls->dns_request != NULL)
    {
        ls->dns_request->cancelled = true;
        ls->dns_request            = NULL;
    }
    ls->resolving = false;
}

void udpconnectorCancelPacketDnsRequests(udpconnector_lstate_t *ls)
{
    udpconnector_packet_dns_request_t *request = ls->packet_dns_requests;

    while (request != NULL)
    {
        udpconnector_packet_dns_request_t *next = request->next;
        request->cancelled                     = true;
        request->prev                          = NULL;
        request->next                          = NULL;
        request                                = next;
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
    udpconnectorCancelDnsRequest(ls);
    udpconnectorCancelPacketDnsRequests(ls);
    udpconnectorPacketDestinationCachesDestroy(ls);
    bufferqueueDestroy(&ls->pause_queue);
    if (ls->idle_handle != NULL)
    {
        LOGF("UdpConnector: idle item still exists for FD:%x ", ls->io ? wioGetFD(ls->io) : -1);
        terminateProgram(1);
    }
    memoryZeroAligned32(ls, sizeof(udpconnector_lstate_t));
}
