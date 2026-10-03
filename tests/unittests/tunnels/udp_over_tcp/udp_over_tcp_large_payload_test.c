/*
 * Covers: udp over tcp large payload; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: testPayload
 * Checks: One length-prefixed callback per accepted datagram, exact content and length, oversized input
 * dropped intact, and UDP destination setup independent of source protocol metadata.
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.udpovertcpclient_large_payload_unit; waterwall.udpovertcpserver_large_payload_unit
 */
/* Source protocol metadata never changes datagram framing or size limits. */
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
#include "fixtures/failure/tunnel_line_failure_harness.h"

static uint32_t expected_length;
static uint32_t payload_calls;

static uint8_t payloadByte(uint32_t index)
{
    return (uint8_t) (index * 17U + 9U);
}

static void encodedSink(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    ++payload_calls;
    const uint8_t *wire = sbufGetRawPtr(buf);
    twfRequire(sbufGetLength(buf) == expected_length + kHeaderSize, "UOT changed the total payload length");
    uint16_t network_length;
    memoryCopy(&network_length, wire, kHeaderSize);
    twfRequire(ntohs(network_length) == expected_length, "UOT changed the datagram length");
    for (uint32_t i = 0; i < expected_length; ++i)
        twfRequire(wire[kHeaderSize + i] == payloadByte(i), "UOT changed datagram content");
    lineReuseBuffer(l, buf);
}

static void testPayload(uint8_t source_protocol, uint32_t length)
{
    twfSetCase("UOT frames one UDP datagram per callback and drops oversized input regardless of source metadata");
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
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(line), source_protocol);
    uot->fnInitU(uot, line);
#ifdef TEST_UOT_SERVER
    twfRequire(lineGetDestinationAddressContext(line)->proto_udp && ! lineGetDestinationAddressContext(line)->proto_tcp,
               "UOT server did not initialize UDP destination");
    prev->fnPayloadD = encodedSink;
#else
    next->fnPayloadU = encodedSink;
#endif
    uot_lstate_t *ls    = lineGetState(line, uot);
    sbuf_t       *input = bufferpoolGetLargeBuffer(env.pool);
    uint8_t      *raw   = sbufGetMutablePtr(input);
    for (uint32_t i = 0; i < length; ++i)
        raw[i] = payloadByte(i);
    sbufSetLength(input, length);
    expected_length = length;
    payload_calls   = 0;
#ifdef TEST_UOT_SERVER
    uot->fnPayloadD(uot, line, input);
#else
    uot->fnPayloadU(uot, line, input);
#endif
    const bool accepted = length <= kMaxAllowedUDPPacketLength;
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
    const uint8_t source_protocols[] = {IP_PROTO_UDP, IP_PROTO_TCP, 0};
    for (unsigned i = 0; i < sizeof(source_protocols); ++i)
    {
        testPayload(source_protocols[i], 1);
        testPayload(source_protocols[i], kMaxAllowedUDPPacketLength);
        testPayload(source_protocols[i], kMaxAllowedUDPPacketLength + 1);
        testPayload(source_protocols[i], LARGE_BUFFER_SIZE_RAM_HIGH);
    }
    return 0;
}
