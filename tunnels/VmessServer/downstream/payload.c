#include "internal.h"

#include "loggers/network_logger.h"

void vmessserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    vmessserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kVmessServerPhaseClosing))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->line_kind == kVmessServerLineKindUdpRemote)
    {
        line_t *client_l = ls->client_line;

        if (UNLIKELY(client_l == NULL || ! lineIsAlive(client_l)))
        {
            lineReuseBuffer(l, buf);
            vmessserverCloseLineBidirectional(t, l);
            return;
        }

        lineRef(l);
        vmessserver_lstate_t *client = lineGetState(client_l, t);
        if (client->packetaddr)
        {
            const address_context_t *target  = &ls->udp_target;
            vmess_packet_addr_t      address = {
                     .address_type = addresscontextIsIpv4(target) ? kVmessAtypIpv4 : kVmessAtypIpv6, .port = target->port};
            memoryCopy(address.address,
                       addresscontextIsIpv4(target) ? (const void *) &target->ip_address.u_addr.ip4.addr
                                                    : (const void *) &target->ip_address.u_addr.ip6,
                       addresscontextIsIpv4(target) ? 4 : 16);
            size_t prefix = vmessPacketAddrHeaderSize(&address);
            size_t length = sbufGetLength(buf);
            if (length > vmessBodyMaxPlaintext(&client->output_crypto) - prefix)
            {
                vmessserverDrop(client, kVmessServerReasonUdpOversize);
                lineReuseBuffer(l, buf);
                lineUnref(l);
                return;
            }
            buffer_pool_t *pool = lineGetBufferPool(l);
            sbuf_t        *wrapped =
                bufferpoolGetBestFit(pool, (uint32_t) (prefix + length), bufferpoolGetLargeBufferPadding(pool));
            size_t           written = 0;
            wcrypto_status_t encoded = vmessPacketAddrEncode(&address, sbufGetMutablePtr(wrapped), prefix, &written);
            assert(encoded == kWCryptoOk && written == prefix);
            discard encoded;
            /* UDP is ordinary, but use the representation helper so all accepted
             * buffers settle through the same ownership path. */
            sbufReadRangeToMemory(buf, sbufGetMutablePtr(wrapped) + prefix, (uint32_t) length);
            sbufSetLength(wrapped, (uint32_t) (prefix + length));
            lineReuseBuffer(l, buf);
            buf = wrapped;
        }
        discard vmessserverForwardResponse(t, client_l, buf);
        lineUnref(l);
        return;
    }

    if (ls->phase == kVmessServerPhaseUdpConnecting || ls->phase == kVmessServerPhaseUdpEstablished)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->phase == kVmessServerPhaseFallback)
    {
        tunnelPrevDownStreamPayload(t, l, buf);
        return;
    }
    discard vmessserverForwardResponse(t, l, buf);
}
