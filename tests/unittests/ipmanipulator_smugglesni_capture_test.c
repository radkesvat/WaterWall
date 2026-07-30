#include "IpManipulator/structure.h"
#include "tricks/smugglesni/trick.h"

#include <stdio.h>
#include <stdlib.h>

typedef struct test_env_s
{
    master_pool_t *large_master;
    master_pool_t *small_master;
    buffer_pool_t *buffer_pool;
    buffer_pool_t *buffer_pools[1];
} test_env_t;

static uint32_t generator_calls;
static uint32_t normal_packets;
static uint32_t real_packets;
static uint16_t last_normal_payload_len;
static uint32_t generated_hello_len;

api_result_t tlsclientTunnelApi(tunnel_t *instance, sbuf_t *message);

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

api_result_t tlsclientTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    discard instance;
    reuseBuffer(message);
    generator_calls++;

    sbuf_t *hello = bufferpoolGetSmallBuffer(getWorkerBufferPool(getWID()));
    sbufSetLength(hello, generated_hello_len);
    memorySet(sbufGetMutablePtr(hello), 0xA5, generated_hello_len);
    return (api_result_t) {.result_code = kApiResultOk, .buffer = hello};
}

static uint16_t tcpPayloadLength(const sbuf_t *buf)
{
    const uint8_t        *packet   = sbufGetRawPtr(buf);
    const struct ip_hdr  *ip       = (const struct ip_hdr *) packet;
    uint16_t              ip_len   = lwip_ntohs(IPH_LEN(ip));
    uint16_t              ip_hlen  = (uint16_t) (IPH_HL(ip) * 4U);
    const struct tcp_hdr *tcp      = (const struct tcp_hdr *) (packet + ip_hlen);
    uint16_t              tcp_hlen = (uint16_t) (TCPH_HDRLEN(tcp) * 4U);
    return (uint16_t) (ip_len - ip_hlen - tcp_hlen);
}

static void receiveNormal(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    normal_packets++;
    last_normal_payload_len = tcpPayloadLength(buf);
    lineReuseBuffer(l, buf);
}

static void receiveReal(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    real_packets++;
    lineReuseBuffer(l, buf);
}

static void envSetup(test_env_t *env)
{
    memoryZero(env, sizeof(*env));
    env->large_master    = masterpoolCreateWithCapacity(32);
    env->small_master    = masterpoolCreateWithCapacity(32);
    env->buffer_pool     = bufferpoolCreate(env->large_master, env->small_master, 32, 8192, 4096);
    env->buffer_pools[0] = env->buffer_pool;

    GSTATE.shortcut_buffer_pools         = env->buffer_pools;
    GSTATE.masterpool_buffer_pools_large = env->large_master;
    GSTATE.masterpool_buffer_pools_small = env->small_master;
    GSTATE.workers_count                 = 2;
    tl_wid                               = 0;
}

static void envTeardown(test_env_t *env)
{
    GSTATE.shortcut_buffer_pools         = NULL;
    GSTATE.masterpool_buffer_pools_large = NULL;
    GSTATE.masterpool_buffer_pools_small = NULL;
    GSTATE.workers_count                 = 0;

    bufferpoolDestroy(env->buffer_pool);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->small_master);
}

static sbuf_t *makeTcpPacket(uint8_t flags, const uint8_t *payload, uint16_t payload_len)
{
    uint16_t packet_len = (uint16_t) (sizeof(struct ip_hdr) + sizeof(struct tcp_hdr) + payload_len);
    sbuf_t  *buf        = bufferpoolGetSmallBuffer(getWorkerBufferPool(getWID()));
    sbufSetLength(buf, packet_len);

    uint8_t *packet = sbufGetMutablePtr(buf);
    memoryZero(packet, packet_len);

    struct ip_hdr *ip = (struct ip_hdr *) packet;
    IPH_VHL_SET(ip, 4, sizeof(struct ip_hdr) / 4U);
    IPH_LEN_SET(ip, lwip_htons(packet_len));
    IPH_PROTO_SET(ip, IPPROTO_TCP);
    ip->src.addr  = PP_HTONL(LWIP_MAKEU32(10, 0, 0, 1));
    ip->dest.addr = PP_HTONL(LWIP_MAKEU32(10, 0, 0, 2));

    struct tcp_hdr *tcp = (struct tcp_hdr *) (packet + sizeof(struct ip_hdr));
    tcp->src            = lwip_htons(12345);
    tcp->dest           = lwip_htons(443);
    TCPH_HDRLEN_FLAGS_SET(tcp, sizeof(struct tcp_hdr) / 4U, flags);

    if (payload_len > 0)
    {
        memoryCopy(packet + sizeof(struct ip_hdr) + sizeof(struct tcp_hdr), payload, payload_len);
    }

    return buf;
}

static tunnel_t *createTestTunnel(tunnel_t *normal, tunnel_t *real)
{
    static char   fake_sni[]  = "fake.example";
    static char   real_name[] = "real-branch";
    static node_t real_node   = {.name = real_name};

    tunnel_t *t = memoryAllocateAlignedZero(sizeof(tunnel_t) + sizeof(ipmanipulator_tstate_t), kCpuLineCacheSize);
    require(t != NULL, "failed to allocate test tunnel");

    t->tstate_size                = sizeof(ipmanipulator_tstate_t);
    t->next                       = normal;
    normal->fnPayloadU            = receiveNormal;
    real->fnPayloadU              = receiveReal;
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    mutexInit(&state->smuggle_flows_mutex);
    state->smuggle_flows_capacity  = kIpManipulatorSmuggleInitialFlows;
    state->smuggle_flows           = memoryAllocateZero(sizeof(*state->smuggle_flows) * state->smuggle_flows_capacity);
    state->trick_smuggle_sni_value = fake_sni;
    state->trick_smuggle_sni_value_len    = (uint16_t) stringLength(state->trick_smuggle_sni_value);
    state->trick_real_sni_upstream_node   = &real_node;
    state->trick_real_sni_upstream_tunnel = real;
    state->trick_smuggle_sni_delay_ms     = 0;
    return t;
}

static void destroyTestTunnel(tunnel_t *t)
{
    smugglesnitrickDestroyState(t);
    memoryFreeAligned(t);
}

static void resetCounters(void)
{
    generator_calls         = 0;
    normal_packets          = 0;
    real_packets            = 0;
    last_normal_payload_len = 0;
}

static void warmFlow(tunnel_t *t, line_t *line)
{
    require(smugglesnitrickUpStreamPayload(t, line, makeTcpPacket(TCP_SYN, NULL, 0)), "SYN was not consumed");
    require(smugglesnitrickUpStreamPayload(t, line, makeTcpPacket(TCP_ACK, NULL, 0)), "ACK was not consumed");
}

static void testNonTlsCaptureFallsThrough(void)
{
    tunnel_t             normal = {0};
    tunnel_t             real   = {0};
    tunnel_t            *t      = createTestTunnel(&normal, &real);
    line_t               line   = {.alive = true, .wid = 0};
    static const uint8_t http[] = "POST / HTTP/1.1\r\n";

    resetCounters();
    warmFlow(t, &line);
    require(smugglesnitrickUpStreamPayload(t, &line, makeTcpPacket(TCP_ACK, http, sizeof(http) - 1)),
            "non-TLS capture packet was not consumed");

    ipmanipulator_tstate_t *state = tunnelGetState(t);
    require(state->smuggle_flows[0].phase == kIpManipulatorSmuggleFlowPhasePassthrough,
            "non-TLS flow did not enter passthrough");
    require(state->smuggle_flows[0].captured_payload_sum == 0, "non-TLS flow retained captured payload bytes");
    require(generator_calls == 0, "non-TLS flow invoked ClientHello generation");
    require(real_packets == 0, "non-TLS capture packet went to the real-SNI branch");
    require(normal_packets == 3, "non-TLS flow did not remain on the normal path");

    destroyTestTunnel(t);
}

static void testTlsCaptureResizesInOneAttempt(void)
{
    tunnel_t  normal           = {0};
    tunnel_t  real             = {0};
    tunnel_t *t                = createTestTunnel(&normal, &real);
    line_t    line             = {.alive = true, .wid = 0};
    uint8_t   client_hello[12] = {0x16, 0x03, 0x03, 0x00, 0x07, 0x01};

    resetCounters();
    generated_hello_len = 37;
    warmFlow(t, &line);
    require(smugglesnitrickUpStreamPayload(t, &line, makeTcpPacket(TCP_ACK, client_hello, sizeof(client_hello))),
            "TLS capture packet was not consumed");

    require(generator_calls == 1, "ClientHello generator was retried");
    require(real_packets == 1, "real ClientHello was not sent immediately");
    require(normal_packets == 3, "fake ClientHello was not sent on the normal path");
    require(last_normal_payload_len == generated_hello_len, "fake ClientHello packet was not resized");

    destroyTestTunnel(t);
}

static void testOversizeGeneratedHelloFallsThrough(void)
{
    tunnel_t  normal           = {0};
    tunnel_t  real             = {0};
    tunnel_t *t                = createTestTunnel(&normal, &real);
    line_t    line             = {.alive = true, .wid = 0};
    uint8_t   client_hello[12] = {0x16, 0x03, 0x03, 0x00, 0x07, 0x01};

    resetCounters();
    generated_hello_len = kMaxAllowedPacketLength;
    warmFlow(t, &line);
    require(smugglesnitrickUpStreamPayload(t, &line, makeTcpPacket(TCP_ACK, client_hello, sizeof(client_hello))),
            "TLS capture packet was not consumed");

    require(generator_calls == 1, "oversize ClientHello generator was retried");
    require(real_packets == 1, "oversize fake prevented the real ClientHello send");
    require(normal_packets == 2, "oversize fake ClientHello was emitted");

    destroyTestTunnel(t);
}

int main(void)
{
    test_env_t env;
    envSetup(&env);
    testNonTlsCaptureFallsThrough();
    testTlsCaptureResizesInOneAttempt();
    testOversizeGeneratedHelloFallsThrough();
    envTeardown(&env);
    return 0;
}
