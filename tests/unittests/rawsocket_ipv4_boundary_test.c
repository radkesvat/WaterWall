#include "tunnel_line_failure_harness.h"

#include "RawSocket/structure.h"

static uint32_t g_raw_write_count;
static uint32_t g_capture_forward_count;

bool __wrap_rawdeviceWrite(raw_device_t *rdev, sbuf_t *buf);

bool __wrap_rawdeviceWrite(raw_device_t *rdev, sbuf_t *buf)
{
    discard rdev;
    discard buf;
    ++g_raw_write_count;

    /* Refuse ownership so the production boundary recycles through the ledger. */
    return false;
}

static void captureForward(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    discard t;
    ++g_capture_forward_count;
    lineReuseBuffer(line, buf);
}

static sbuf_t *makeRawLength(buffer_pool_t *pool, uint32_t length)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(pool);
    twfRequire(buf != NULL && length <= sbufGetTotalCapacityNoPadding(buf), "failed to allocate a RawSocket packet");
    sbufSetLength(buf, length);
    if (length > 0)
    {
        memoryZero(sbufGetMutablePtr(buf), length);
    }
    return buf;
}

static sbuf_t *makeIpv4(buffer_pool_t *pool, uint32_t length)
{
    sbuf_t *buf = makeRawLength(pool, length);
    twfRequire(length >= IP_HLEN, "an IPv4 fixture is shorter than its base header");

    struct ip_hdr *ip = (struct ip_hdr *) (void *) sbufGetMutablePtr(buf);
    IPH_VHL_SET(ip, 4, IP_HLEN / 4);
    IPH_LEN_SET(ip, lwip_htons(length));
    IPH_ID_SET(ip, lwip_htons(0x1234));
    IPH_TTL_SET(ip, 64);
    IPH_PROTO_SET(ip, 253);
    ip->src.addr  = PP_HTONL(LWIP_MAKEU32(192, 0, 2, 10));
    ip->dest.addr = PP_HTONL(LWIP_MAKEU32(198, 51, 100, 20));
    return buf;
}

static void requireOutputDropped(tunnel_t *t, line_t *line, sbuf_t *buf, const char *message)
{
    twfBufferLedgerReset();
    g_raw_write_count          = 0;
    line->recalculate_checksum = false;
    rawsocketWriteStreamPayload(t, line, buf);
    twfRequireEqualU32(g_raw_write_count, 0, message);
    twfRequireEqualU32(g_twf_buffers.total_recycled, 1, "RawSocket did not recycle invalid output exactly once");
}

static void requireOutputOffered(tunnel_t *t, line_t *line, sbuf_t *buf, const char *message)
{
    twfBufferLedgerReset();
    g_raw_write_count          = 0;
    line->recalculate_checksum = false;
    rawsocketWriteStreamPayload(t, line, buf);
    twfRequireEqualU32(g_raw_write_count, 1, message);
    twfRequireEqualU32(g_twf_buffers.total_recycled, 1, "RawSocket did not recycle a refused valid output once");
}

static void requireIngressDropped(capture_device_t *capture, tunnel_t *t, buffer_pool_t *pool, sbuf_t *buf,
                                  const char *message)
{
    twfBufferLedgerReset();
    g_capture_forward_count = 0;
    rawsocketOnIPPacketReceived(capture, t, buf, 0);
    twfRequireEqualU32(g_capture_forward_count, 0, message);
    twfRequireEqualU32(g_twf_buffers.total_recycled, 1, "RawSocket did not recycle invalid ingress exactly once");
    discard pool;
}

static void requireIngressForwarded(capture_device_t *capture, tunnel_t *t, sbuf_t *buf, const char *message)
{
    twfBufferLedgerReset();
    g_capture_forward_count = 0;
    rawsocketOnIPPacketReceived(capture, t, buf, 0);
    twfRequireEqualU32(g_capture_forward_count, 1, message);
    twfRequireEqualU32(g_twf_buffers.total_recycled, 1, "RawSocket forwarded ingress with wrong ownership");
}

int main(void)
{
    twf_worker_env_t env;
    twf_line_pool_t  line_pool;
    twfWorkerEnvSetup(&env, 4096, 0);
    twfLinePoolSetup(&line_pool, 0, 2);

    tunnel_t *t          = tunnelCreate(NULL, sizeof(rawsocket_tstate_t), 0);
    tunnel_t *forwarding = tunnelCreate(NULL, 0, 0);
    line_t   *line       = twfLinePoolCreateLine(&line_pool);
    twfRequire(t != NULL && forwarding != NULL && line != NULL, "failed to create the RawSocket boundary fixture");

    raw_device_t        fake_raw = {0};
    rawsocket_tstate_t *state    = tunnelGetState(t);
    state->raw_device            = &fake_raw;

    forwarding->fnPayloadU = captureForward;
    t->next                = forwarding;
    forwarding->prev       = t;
    twfRequire(packettunnelConfigureLifecycleAnchor(
                   t, "RawSocket test", rawsocketWriteStreamPayload, kPacketLifecycleAnchorPublishUpstream),
               "failed to configure the RawSocket lifecycle anchor");
    twfRequire(packettunnelLifecycleAnchorBind(t), "failed to bind the RawSocket lifecycle anchor");

    line_t          *packet_lines[] = {line};
    tunnel_chain_t   chain          = {.workers_count = 1, .packet_lines = packet_lines};
    capture_device_t capture        = {0};
    atomic_init(&capture.up, true);
    t->chain = &chain;

    buffer_pool_t *pool = lineGetBufferPool(line);

    twfSetCase("RawSocket output validates IPv4 even without checksum work");
    requireOutputDropped(t, line, makeRawLength(pool, 0), "zero-length output reached the raw writer");
    requireOutputDropped(t, line, makeRawLength(pool, IP_HLEN - 1U), "short output reached the raw writer");

    sbuf_t *packet = makeIpv4(pool, IP_HLEN + 1U);
    IPH_LEN_SET((struct ip_hdr *) (void *) sbufGetMutablePtr(packet), lwip_htons(IP_HLEN));
    requireOutputDropped(t, line, packet, "output with trailing bytes reached the raw writer");

    packet                       = makeRawLength(pool, IP_HLEN);
    sbufGetMutablePtr(packet)[0] = 0x60;
    requireOutputDropped(t, line, packet, "IPv6 output reached the raw writer");

    packet = makeRawLength(pool, IP_HLEN + 1U);
    sbufShiftRight(packet, 1U);
    IPH_VHL_SET((struct ip_hdr *) (void *) sbufGetMutablePtr(packet), 4, IP_HLEN / 4);
    IPH_LEN_SET((struct ip_hdr *) (void *) sbufGetMutablePtr(packet), lwip_htons(IP_HLEN));
    requireOutputOffered(t, line, packet, "misaligned valid IPv4 output was rejected");

    twfSetCase("RawSocket ingress validates before dispatch");
    requireIngressDropped(&capture, t, pool, makeRawLength(pool, 1), "short ingress was dispatched");

    packet = makeIpv4(pool, IP_HLEN + 1U);
    IPH_LEN_SET((struct ip_hdr *) (void *) sbufGetMutablePtr(packet), lwip_htons(IP_HLEN));
    requireIngressDropped(&capture, t, pool, packet, "ingress with trailing bytes was dispatched");

    packet                       = makeRawLength(pool, IP_HLEN);
    sbufGetMutablePtr(packet)[0] = 0x60;
    requireIngressDropped(&capture, t, pool, packet, "IPv6 ingress was dispatched");

    packet = makeRawLength(pool, IP_HLEN + 4U);
    IPH_VHL_SET((struct ip_hdr *) (void *) sbufGetMutablePtr(packet), 4, (IP_HLEN + 4U) / 4U);
    IPH_LEN_SET((struct ip_hdr *) (void *) sbufGetMutablePtr(packet), lwip_htons(IP_HLEN + 4U));
    requireIngressForwarded(&capture, t, packet, "valid IPv4 options were not dispatched");

    packet = makeIpv4(pool, IP_HLEN + 8U);
    IPH_OFFSET_SET((struct ip_hdr *) (void *) sbufGetMutablePtr(packet), lwip_htons(1U));
    requireIngressForwarded(&capture, t, packet, "a valid later IPv4 fragment was not dispatched");

    lineDestroy(line);
    tunnelDestroy(forwarding);
    tunnelDestroy(t);
    twfLinePoolTeardown(&line_pool);
    twfWorkerEnvTeardown(&env);
    puts("RawSocket IPv4 boundary tests passed");
    return 0;
}
