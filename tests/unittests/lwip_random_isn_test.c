#include "lwip_test_runtime.h"

static atomic_bool g_tcpip_initialized;

static const uint8_t kFastRandomKey[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};

static const uint8_t kIsnSecret[kWwLwipTcpIsnSecretSize] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "lwip_random_isn_test: %s\n", message);
        exit(1);
    }
}

static ip_addr_t parseAddress(const char *text)
{
    ip_addr_t address;
    require(ipaddr_aton(text, &address) != 0, "failed to parse a test address");
    return address;
}

static void tcpipInitialized(void *argument)
{
    discard argument;
    frandInit();
    atomicStoreExplicit(&g_tcpip_initialized, true, memory_order_release);
}

static void caseLwipRandUsesCachedFastStream(void)
{
    wfrandTestReset(kFastRandomKey, 17);
    const uint32_t expected = fastRand32();

    wfrandTestReset(kFastRandomKey, 17);
    require(lwip_port_rand() == expected, "LWIP_RAND did not consume the next fastRand32 word");

    globalstateDestroySecureRandom();
    wfrandTestReset(kFastRandomKey, 29);
    const uint32_t expected_without_provider = fastRand32();
    wfrandTestReset(kFastRandomKey, 29);
    require(lwip_port_rand() == expected_without_provider,
            "LWIP_RAND depended on the destroyed operating-system provider");
}

static void caseTcpIsnCanonicalVectors(void)
{
    const ip_addr_t local_v4  = parseAddress("192.0.2.1");
    const ip_addr_t remote_v4 = parseAddress("198.51.100.2");
    const ip_addr_t local_v6  = parseAddress("2001:db8::1");
    const ip_addr_t remote_v6 = parseAddress("2001:db8:1::2");

    static const uint8_t expected_v4_tuple[kWwLwipTcpIsnTupleSize] = {
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
        0xC0, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xFF, 0xFF, 0xC6, 0x33, 0x64, 0x02, 0x30, 0x39, 0x01, 0xBB,
    };
    static const uint8_t expected_v6_tuple[kWwLwipTcpIsnTupleSize] = {
        0x06, 0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xFF, 0xFF, 0x00, 0x01,
    };

    uint8_t tuple[kWwLwipTcpIsnTupleSize];
    wwLwipTestSetTcpIsnSecret(kIsnSecret);
    wwLwipTestSerializeTcpIsnTuple(tuple, &local_v4, 12345, &remote_v4, 443);
    require(memoryEqual(tuple, expected_v4_tuple, sizeof(tuple)),
            "IPv4 tuple serialization was not the canonical 37-byte encoding");
    require(wwLwipTestTcpIsnAt(&local_v4, 12345, &remote_v4, 443, UINT32_C(0x01020304)) == UINT32_C(0x936E986D),
            "fixed IPv4 TCP ISN vector mismatch");

    wwLwipTestSerializeTcpIsnTuple(tuple, &local_v6, UINT16_MAX, &remote_v6, 1);
    require(memoryEqual(tuple, expected_v6_tuple, sizeof(tuple)),
            "IPv6 tuple serialization was not the canonical 37-byte encoding");
    require(wwLwipTestTcpIsnAt(&local_v6, UINT16_MAX, &remote_v6, 1, 5000) == UINT32_C(0x333FDFA9),
            "fixed IPv6 TCP ISN vector mismatch");
}

static void caseTcpIsnInputsAndClockAreBound(void)
{
    const ip_addr_t local         = parseAddress("192.0.2.1");
    const ip_addr_t local_other   = parseAddress("192.0.2.9");
    const ip_addr_t remote        = parseAddress("198.51.100.2");
    const ip_addr_t remote_other  = parseAddress("198.51.100.9");
    const ip_addr_t local_mapped  = parseAddress("::ffff:192.0.2.1");
    const ip_addr_t remote_mapped = parseAddress("::ffff:198.51.100.2");

    wwLwipTestSetTcpIsnSecret(kIsnSecret);
    const uint32_t base = wwLwipTestTcpIsnAt(&local, 12345, &remote, 443, 0);
    require(base == wwLwipTestTcpIsnAt(&local, 12345, &remote, 443, 0),
            "identical secret, tuple, and time changed the TCP ISN");
    require(base != wwLwipTestTcpIsnAt(&local_other, 12345, &remote, 443, 0),
            "local address was absent from the TCP ISN PRF");
    require(base != wwLwipTestTcpIsnAt(&local, 12345, &remote_other, 443, 0),
            "remote address was absent from the TCP ISN PRF");
    require(base != wwLwipTestTcpIsnAt(&local, 12346, &remote, 443, 0), "local port was absent from the TCP ISN PRF");
    require(base != wwLwipTestTcpIsnAt(&local, 12345, &remote, 444, 0), "remote port was absent from the TCP ISN PRF");
    require(base != wwLwipTestTcpIsnAt(&local_mapped, 12345, &remote_mapped, 443, 0),
            "address-family discriminator was absent from the TCP ISN PRF");

    uint8_t other_secret[kWwLwipTcpIsnSecretSize];
    memoryCopy(other_secret, kIsnSecret, sizeof(other_secret));
    other_secret[31] ^= 0x80;
    wwLwipTestSetTcpIsnSecret(other_secret);
    require(base != wwLwipTestTcpIsnAt(&local, 12345, &remote, 443, 0), "TCP ISN secret did not affect the PRF result");

    wwLwipTestSetTcpIsnSecret(kIsnSecret);
    const uint32_t before_wrap = wwLwipTestTcpIsnAt(&local, 12345, &remote, 443, UINT32_MAX);
    const uint32_t after_wrap  = wwLwipTestTcpIsnAt(&local, 12345, &remote, 443, 0);
    require((uint32_t) (after_wrap - before_wrap) == UINT32_C(250),
            "one millisecond did not advance the TCP ISN clock by exactly 250 modulo 2^32");
}

int main(void)
{
    require(lwipTestRuntimeInitialize(), "failed to initialize the lwIP random runtime");
    require(wwLwipTestTcpIsnSecretIsInitialized(), "TCP ISN secret was absent before tcpip_init");

    caseTcpIsnCanonicalVectors();
    caseTcpIsnInputsAndClockAreBound();
    caseLwipRandUsesCachedFastStream();

    wwLwipTestEraseTcpIsnSecret();
    require(! wwLwipTestTcpIsnSecretIsInitialized(), "test erasure left the TCP ISN secret initialized");
    wwLwipTestSetTcpIsnSecret(kIsnSecret);

    atomic_init(&g_tcpip_initialized, false);
    tcpip_init(tcpipInitialized, NULL);
    while (! atomicLoadExplicit(&g_tcpip_initialized, memory_order_acquire))
    {
        YIELD_THREAD();
    }
    require(wwLwipShutdown(), "failed to join the lwIP thread");
    require(! wwLwipTestTcpIsnSecretIsInitialized(), "joined lwIP shutdown did not erase the TCP ISN secret");

    lwipTestRuntimeCleanup();
    puts("lwip_random_isn_test: all cases passed");
    return 0;
}
