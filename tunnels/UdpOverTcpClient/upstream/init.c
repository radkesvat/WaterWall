#include "structure.h"

#include "loggers/network_logger.h"

static bool udpovertcpclientLineIsTcp(const line_t *l)
{
    const address_context_t *src_ctx = lineGetSourceAddressContext((line_t *) l);

    return src_ctx->proto_tcp && ! src_ctx->proto_udp && ! src_ctx->proto_icmp && ! src_ctx->proto_packet;
}

static bool udpovertcpclientLineIsUdp(const line_t *l)
{
    const address_context_t *src_ctx = lineGetSourceAddressContext((line_t *) l);

    return src_ctx->proto_udp && ! src_ctx->proto_tcp && ! src_ctx->proto_icmp && ! src_ctx->proto_packet;
}

static bool udpovertcpclientSendProtocolMarker(tunnel_t *t, line_t *l, uint8_t protocol)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(l));
    uint8_t *ptr;

    sbufSetLength(buf, kProtocolMarkerSize);
    ptr = sbufGetMutablePtr(buf);
    ptr[0] = 0;
    ptr[1] = 0;
    ptr[2] = protocol;

    return withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, buf);
}

void udpovertcpclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    udpovertcpclient_lstate_t *ls = lineGetState(l, t);
    uint8_t protocol_marker = udpovertcpclientLineIsTcp(l) ? IP_PROTO_TCP : IP_PROTO_UDP;
    bool send_protocol_marker = ! udpovertcpclientLineIsUdp(l);

    udpovertcpclientLinestateInitialize(ls, lineGetBufferPool(l));

    if (! withLineLocked(l, tunnelNextUpStreamInit, t))
    {
        return;
    }

    if (send_protocol_marker)
    {
        discard udpovertcpclientSendProtocolMarker(t, l, protocol_marker);
    }
}
