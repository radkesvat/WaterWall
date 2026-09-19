/* TCP callbacks may exceed a UDP frame; UDP callbacks remain one datagram. */
#ifdef TEST_UOT_SERVER
#include "UdpOverTcpServer/structure.h"
#define createUot       udpovertcpserverTunnelCreate
#define destroyUotState udpovertcpserverLinestateDestroy
typedef udpovertcpserver_lstate_t uot_lstate_t;
#else
#include "UdpOverTcpClient/structure.h"
#define createUot       udpovertcpclientTunnelCreate
#define destroyUotState udpovertcpclientLinestateDestroy
typedef udpovertcpclient_lstate_t uot_lstate_t;
#endif
#include "tunnel_line_failure_harness.h"

static uint32_t         expected_length;
static uint32_t         payload_calls;

static uint8_t payloadByte(uint32_t index)
{
    return (uint8_t) (index * 17U + 9U);
}

static void encodedSink(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    ++payload_calls;
    const uint8_t *wire     = sbufGetRawPtr(buf);
    uint32_t       offset   = 0;
    uint32_t       consumed = 0;
    while (offset < sbufGetLength(buf))
    {
        twfRequire(sbufGetLength(buf) - offset >= kHeaderSize, "UOT emitted an incomplete header");
        uint16_t network_length;
        memoryCopy(&network_length, wire + offset, kHeaderSize);
        const uint32_t length = ntohs(network_length);
        offset += kHeaderSize;
        twfRequire(length > 0 && length <= kMaxAllowedUDPPacketLength && length <= sbufGetLength(buf) - offset,
                   "UOT emitted an invalid data frame length");
        for (uint32_t i = 0; i < length; ++i)
            twfRequire(wire[offset + i] == payloadByte(consumed + i), "UOT changed TCP byte order or content");
        consumed += length;
        offset += length;
    }
    twfRequire(consumed == expected_length, "UOT changed the total payload length");
    lineReuseBuffer(l, buf);
}

static void testPayload(bool tcp, uint32_t length)
{
    twfSetCase(tcp ? "UOT fragments large TCP payloads in one callback" : "UOT preserves UDP datagram limits");
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, LARGE_BUFFER_SIZE_RAM_HIGH, 32);
    twf_trace_t trace = {0};
    tunnel_t   *prev  = twfCreatePrevTunnel(&trace);
    tunnel_t   *uot   = createUot(NULL);
    tunnel_t   *next  = twfCreateNextTunnel(&trace);
    twfRequire(uot != NULL, "could not create UOT");
    tunnelBind(prev, uot);
    tunnelBind(uot, next);
    line_t *line = twfLineCreate(uot->lstate_size);
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(line), tcp ? IP_PROTO_TCP : IP_PROTO_UDP);
    uot->fnInitU(uot, line);
#ifdef TEST_UOT_SERVER
    sbuf_t  *marker = bufferpoolGetSmallBuffer(env.pool);
    uint8_t *bytes  = sbufGetMutablePtr(marker);
    bytes[0]        = 0;
    bytes[1]        = 0;
    bytes[2]        = tcp ? IP_PROTO_TCP : IP_PROTO_UDP;
    sbufSetLength(marker, kProtocolMarkerSize);
    uot->fnPayloadU(uot, line, marker);
    prev->fnPayloadD = encodedSink;
#else
    next->fnPayloadU = encodedSink;
#endif
    uot_lstate_t *ls = lineGetState(line, uot);
    twfRequire(ls->tcp_mode == tcp, "UOT did not preserve its negotiated payload mode");
    sbuf_t  *input = bufferpoolGetLargeBuffer(env.pool);
    uint8_t *raw   = sbufGetMutablePtr(input);
    for (uint32_t i = 0; i < length; ++i)
        raw[i] = payloadByte(i);
    sbufSetLength(input, length);
    expected_length          = length;
    payload_calls            = 0;
#ifdef TEST_UOT_SERVER
    uot->fnPayloadD(uot, line, input);
#else
    uot->fnPayloadU(uot, line, input);
#endif
    const bool accepted = tcp || length <= kMaxAllowedUDPPacketLength;
    twfRequire(payload_calls == (accepted ? 1U : 0U),
               "UOT emitted multiple callbacks or accepted an oversized datagram");
    destroyUotState(ls);
    twfLineDestroy(line);
    tunnelDestroy(uot);
    tunnelDestroy(prev);
    tunnelDestroy(next);
    twfRequireNoLeakedBuffers();
    twfWorkerEnvTeardown(&env);
}

int main(void)
{
    testPayload(true, kMaxAllowedUDPPacketLength);
    testPayload(true, kMaxAllowedUDPPacketLength + 1);
    testPayload(true, LARGE_BUFFER_SIZE_RAM_HIGH);
    testPayload(false, kMaxAllowedUDPPacketLength);
    testPayload(false, kMaxAllowedUDPPacketLength + 1);
    return 0;
}
