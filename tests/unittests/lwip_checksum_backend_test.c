#include "lwip/init.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/stats.h"
#include "lwip_test_runtime.h"
#include "wchecksum.h"
#include <sys/mman.h>
#include <unistd.h>

/* Only this executable compiles a private dispatch instance. No runtime test
 * switch is added to the production checksum provider. */
#ifdef WW_CHECKSUM_TEST_VARIANT
#include "../../ww/net/wchecksum.c"
#endif

/* Two all-ones 64-bit words followed by one: adding the saved carry to
 * UINT64_MAX must itself carry around instead of becoming raw zero. */
static const uint8_t carry_input[24] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 1,
};

static unsigned hook_calls;
uint16_t        __real_wwLwipChecksum(const void *data, int length);
uint16_t        __wrap_wwLwipChecksum(const void *data, int length);
uint16_t        __wrap_wwLwipChecksum(const void *data, int length)
{
    ++hook_calls;
    return __real_wwLwipChecksum(data, length);
}

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "lwip_checksum_backend_test: %s\n", message);
        exit(1);
    }
}

/* Independent byte-by-byte network-order oracle, with bounded carry folding. */
static uint16_t rawOracle(const uint8_t *bytes, size_t length)
{
    uint32_t sum = 0;
    for (size_t i = 0; i < length; ++i)
    {
        sum += (uint32_t) bytes[i] << ((i & 1) ? 0 : 8);
        sum = (sum & 0xffffU) + (sum >> 16);
    }
    return (uint16_t) sum;
}

static void checkBytes(uint16_t actual, uint16_t network_value, const char *message)
{
    const uint8_t *bytes = (const uint8_t *) &actual;
    require(bytes[0] == (network_value >> 8) && bytes[1] == (network_value & 255), message);
}

static void store16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t) (value >> 8);
    bytes[1] = (uint8_t) value;
}

static void testCarrySpans(void)
{
    uint8_t storage[sizeof(carry_input) + 63], copy[sizeof(carry_input)];
    require(rawOracle(carry_input, sizeof(carry_input)) == 1, "carry vector oracle");
    for (size_t offset = 0; offset < 64; ++offset)
    {
        uint8_t *data = storage + offset;
        memcpy(data, carry_input, sizeof(carry_input));
        checkBytes(wwLwipChecksum(data, sizeof(carry_input)), 1, "carry vector raw sum");
        checkBytes(inet_chksum(data, sizeof(carry_input)), 0xfffe, "carry vector checksum");
        struct pbuf p = {0};
        p.payload     = data;
        p.len = p.tot_len = sizeof(carry_input);
        checkBytes(inet_chksum_pbuf(&p), 0xfffe, "carry vector pbuf checksum");
        checkBytes(lwip_chksum_copy(copy, data, sizeof(copy)), 1, "carry vector copy sum");
        require(memcmp(copy, carry_input, sizeof(copy)) == 0, "carry vector copy bytes");

        /* Fold the seed as four network-order bytes in the independent oracle.
         * Sixteen ff bytes also exercise carry when adding a nonzero seed. */
        const uint32_t seeds[] = {0, 1, 0xffff, 0x10000, UINT32_MAX};
        for (size_t i = 0; i < ARRAY_SIZE(seeds); ++i)
        {
            uint8_t seeded[4 + sizeof(carry_input)];
            store16(seeded, (uint16_t) (seeds[i] >> 16));
            store16(seeded + 2, (uint16_t) seeds[i]);
            memcpy(seeded + 4, data, sizeof(carry_input));
            checkBytes(calcGenericChecksum(data, 16, seeds[i]),
                       (uint16_t) ~rawOracle(seeded, 4 + 16),
                       "carry vector seeded prefix");
            checkBytes(calcGenericChecksum(data, sizeof(carry_input), seeds[i]),
                       (uint16_t) ~rawOracle(seeded, sizeof(seeded)),
                       "carry vector seeded checksum");
        }
        require(memcmp(data, carry_input, sizeof(carry_input)) == 0, "carry vector source changed");
    }
}

static void fill(uint8_t *bytes, size_t length, unsigned pattern)
{
    uint32_t state = 0x372819ab;
    for (size_t i = 0; i < length; ++i)
    {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        bytes[i] = pattern == 0 ? 0 : pattern == 1 ? 255 : pattern == 2 ? (uint8_t) i : (uint8_t) state;
    }
}

static void testSpans(void)
{
    static const int lengths[] = {0,  1,  2,  3,  7,    8,     15,    16,    20,     31,     32,
                                  33, 63, 64, 65, 1500, 65534, 65535, 65536, 131068, 131069, 196607};
    const size_t     capacity  = 196607 + 64;
    uint8_t         *bytes = malloc(capacity), *saved = malloc(capacity), *copy = malloc(capacity);
    require(bytes && saved && copy, "span allocation");
    require(wwLwipChecksum(NULL, 0) == 0, "empty raw sum");
    const uint8_t known[] = {1, 2};
    checkBytes(wwLwipChecksum(known, 2), 0x0102, "known raw bytes");
    checkBytes(inet_chksum(known, 2), 0xfefd, "known completed bytes");
    for (unsigned pattern = 0; pattern < 4; ++pattern)
    {
        fill(bytes, capacity, pattern);
        memcpy(saved, bytes, capacity);
        for (int offset = 0; offset < 64; ++offset)
        {
            for (size_t n = 0; n < ARRAY_SIZE(lengths); ++n)
            {
                const int      length = lengths[n];
                const uint16_t raw    = rawOracle(bytes + offset, (size_t) length);
                checkBytes(wwLwipChecksum(bytes + offset, length), raw, "span raw checksum");
                if (length <= UINT16_MAX)
                {
                    unsigned before = hook_calls;
                    checkBytes(inet_chksum(bytes + offset, (u16_t) length), (uint16_t) ~raw, "inet checksum");
                    require(hook_calls > before, "inet_chksum bypassed adapter");
                    memset(copy, 0x5a, capacity);
                    before = hook_calls;
                    checkBytes(lwip_chksum_copy(copy + offset, bytes + offset, (u16_t) length), raw, "copy checksum");
                    require(hook_calls > before, "copy bypassed adapter");
                    require(memcmp(copy + offset, bytes + offset, (size_t) length) == 0, "copy bytes");
                    require(copy[offset + length] == 0x5a && (offset == 0 || copy[offset - 1] == 0x5a), "copy bounds");
                }
            }
        }
        require(memcmp(bytes, saved, capacity) == 0, "checksum mutated source");
    }
    free(copy);
    free(saved);
    free(bytes);

    /* Every small tail alignment, plus each wide/chunk boundary, ends exactly
     * at an inaccessible page. A second guard also catches reads before input. */
    const size_t page       = (size_t) sysconf(_SC_PAGESIZE);
    const size_t accessible = ((196607 + page - 1) / page) * page;
    uint8_t     *map        = mmap(NULL, accessible + 2 * page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    require(map != MAP_FAILED, "guard mapping");
    require(mprotect(map + page, accessible, PROT_READ | PROT_WRITE) == 0, "guard protection");
    fill(map + page, accessible, 3);
    require(mprotect(map + page, accessible, PROT_READ) == 0, "read-only source");
    for (int n = 0; n < 128 + (int) ARRAY_SIZE(lengths); ++n)
    {
        int            length = n < 128 ? n : lengths[n - 128];
        const uint8_t *tail   = map + page + accessible - length;
        checkBytes(wwLwipChecksum(tail, length), rawOracle(tail, (size_t) length), "guarded tail");
        checkBytes(wwLwipChecksum(map + page, length), rawOracle(map + page, (size_t) length), "guarded head");
    }
    require(munmap(map, accessible + 2 * page) == 0, "guard unmap");
}

static uint16_t pseudoOracle(const uint8_t *data, size_t coverage, uint16_t length, uint8_t proto, const ip_addr_t *src,
                             const ip_addr_t *dst)
{
    uint8_t bytes[40 + 2048] = {0};
    size_t  header;
    if (IP_IS_V6(src))
    {
        memcpy(bytes, ip_2_ip6(src)->addr, 16);
        memcpy(bytes + 16, ip_2_ip6(dst)->addr, 16);
        store16(bytes + 34, length);
        bytes[39] = proto;
        header    = 40;
    }
    else
    {
        memcpy(bytes, &ip_2_ip4(src)->addr, 4);
        memcpy(bytes + 4, &ip_2_ip4(dst)->addr, 4);
        bytes[9] = proto;
        store16(bytes + 10, length);
        header = 12;
    }
    require(coverage <= 2048, "oracle input bound");
    memcpy(bytes + header, data, coverage);
    return (uint16_t) ~rawOracle(bytes, header + coverage);
}

static ip_addr_t address(const char *text)
{
    ip_addr_t result;
    require(ipaddr_aton(text, &result), "address parse");
    return result;
}

static void testChains(void)
{
    static const uint16_t partitions[][6] = {
        {1501, 0, 0, 0, 0, 0}, {1, 2, 0, 63, 1435, 0}, {0, 3, 7, 8, 0, 1483}, {32, 64, 65, 0, 1339, 1}};
    uint8_t logical[1501], storage[6][1504];
    fill(logical, sizeof(logical), 3);
    for (size_t part = 0; part < ARRAY_SIZE(partitions); ++part)
    {
        struct pbuf chain[6] = {0};
        size_t      offset   = 0;
        for (size_t i = 0; i < 6; ++i)
        {
            chain[i].payload = storage[i] + i + 1;
            chain[i].len     = partitions[part][i];
            chain[i].tot_len = (u16_t) (sizeof(logical) - offset);
            chain[i].next    = i < 5 ? &chain[i + 1] : NULL;
            memcpy(chain[i].payload, logical + offset, chain[i].len);
            offset += chain[i].len;
        }
        require(offset == sizeof(logical), "partition length");
        unsigned before = hook_calls;
        checkBytes(inet_chksum_pbuf(chain), (uint16_t) ~rawOracle(logical, sizeof(logical)), "chain checksum");
        require(hook_calls == before + 6, "pbuf hook routing");
        for (int v6 = 0; v6 < 2; ++v6)
        {
            const ip_addr_t src = address(v6 ? "2001:db8::1" : "192.0.2.1");
            const ip_addr_t dst = address(v6 ? "2001:db8:2::9" : "198.51.100.9");
            for (uint8_t proto = IP_PROTO_TCP; proto <= IP_PROTO_UDP; proto += IP_PROTO_UDP - IP_PROTO_TCP)
            {
                before = hook_calls;
                checkBytes(ip_chksum_pseudo(chain, proto, sizeof(logical), &src, &dst),
                           pseudoOracle(logical, sizeof(logical), sizeof(logical), proto, &src, &dst),
                           "pseudoheader");
                require(hook_calls == before + 6, "pseudoheader hook routing");
                const uint16_t coverage[] = {0, 1, 2, 9, 31, 100, 1499, 1501};
                for (size_t k = 0; k < ARRAY_SIZE(coverage); ++k)
                {
                    before = hook_calls;
                    checkBytes(ip_chksum_pseudo_partial(chain, proto, sizeof(logical), coverage[k], &src, &dst),
                               pseudoOracle(logical, coverage[k], sizeof(logical), proto, &src, &dst),
                               "partial pseudoheader");
                    require(coverage[k] == 0 || hook_calls > before, "partial hook routing");
                }
            }
        }
    }
}

static unsigned outputs, received;
static uint8_t  last_packet[2048];
static uint16_t last_length;

static err_t outputPacket(struct netif *netif, struct pbuf *p, const ip4_addr_t *dest)
{
    (void) netif;
    (void) dest;
    require(p->tot_len <= sizeof(last_packet), "output length");
    last_length = pbuf_copy_partial(p, last_packet, p->tot_len, 0);
    require(last_length == p->tot_len, "output copy");
    require(rawOracle(last_packet, 20) == 0xffff, "inline IPv4 output checksum");
    ip_addr_t src, dst;
    IP_ADDR4(&src, last_packet[12], last_packet[13], last_packet[14], last_packet[15]);
    IP_ADDR4(&dst, last_packet[16], last_packet[17], last_packet[18], last_packet[19]);
    require(pseudoOracle(last_packet + 20, last_length - 20, last_length - 20, last_packet[9], &src, &dst) == 0,
            "protocol output checksum");
    ++outputs;
    return ERR_OK;
}

static err_t netifInit(struct netif *netif)
{
    netif->name[0] = 'c';
    netif->name[1] = 'k';
    netif->mtu     = 1500;
    netif->output  = outputPacket;
    return ERR_OK;
}

static void receiveUdp(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *src, u16_t port)
{
    (void) arg;
    (void) pcb;
    (void) src;
    (void) port;
    ++received;
    pbuf_free(p);
}

static void inputPacket(struct netif *netif, uint8_t *packet, uint16_t length)
{
    struct pbuf *p = pbuf_alloc(PBUF_RAW, length, PBUF_RAM);
    require(p != NULL, "input allocation");
    require(pbuf_take(p, packet, length) == ERR_OK, "input copy");
    require(ip4_input(p, netif) == ERR_OK, "input submission");
}

static void testProtocols(void)
{
    const ip_addr_t local = address("192.0.2.1"), remote = address("192.0.2.2");
    ip4_addr_t      mask, gateway;
    IP4_ADDR(&mask, 255, 255, 255, 0);
    ip4_addr_set_zero(&gateway);
    struct netif netif = {0};
    require(netif_add(&netif, ip_2_ip4(&local), &mask, &gateway, NULL, netifInit, ip4_input) != NULL, "netif add");
    netif_set_up(&netif);
    netif_set_link_up(&netif);
    netif_set_default(&netif);
    struct udp_pcb *udp = udp_new();
    require(udp && udp_bind(udp, &local, 9000) == ERR_OK, "UDP bind");
    udp_recv(udp, receiveUdp, NULL);
    uint8_t packet[42] = {0x45};
    store16(packet + 2, 30);
    packet[8] = 64;
    packet[9] = IP_PROTO_UDP;
    memcpy(packet + 12, &ip_2_ip4(&remote)->addr, 4);
    memcpy(packet + 16, &ip_2_ip4(&local)->addr, 4);
    store16(packet + 10, (uint16_t) ~rawOracle(packet, 20));
    store16(packet + 20, 8000);
    store16(packet + 22, 9000);
    store16(packet + 24, 10);
    packet[28] = 0x12;
    packet[29] = 0x34;
    store16(packet + 26, pseudoOracle(packet + 20, 10, 10, IP_PROTO_UDP, &remote, &local));
    unsigned before = received;
    inputPacket(&netif, packet, 30);
    require(received == before + 1, "valid UDP rejected");
    packet[28] ^= 1;
    inputPacket(&netif, packet, 30);
    require(received == before + 1, "corrupt UDP accepted");
    store16(packet + 26, 0);
    inputPacket(&netif, packet, 30);
    require(received == before + 2, "disabled IPv4 UDP checksum rejected");
    store16(packet + 28, 0);
    store16(packet + 28, pseudoOracle(packet + 20, 10, 10, IP_PROTO_UDP, &remote, &local));
    store16(packet + 26, 0xffff);
    inputPacket(&netif, packet, 30);
    require(received == before + 3, "enabled UDP arithmetic zero rejected");

    /* Same ports reversed on output: one's-complement addition is commutative. */
    struct pbuf *payload = pbuf_alloc(PBUF_TRANSPORT, 2, PBUF_RAM);
    require(payload && pbuf_take(payload, packet + 28, 2) == ERR_OK, "UDP output payload");
    require(udp_sendto_if(udp, payload, &remote, 8000, &netif) == ERR_OK, "UDP send");
    require(last_packet[26] == 255 && last_packet[27] == 255, "UDP output zero normalization");
    pbuf_free(payload);
    udp_remove(udp);

    struct tcp_pcb *tcp;
    for (unsigned carry_case = 0; carry_case < 2; ++carry_case)
    {
        tcp = tcp_new();
        require(tcp && tcp_bind(tcp, &local, 9001) == ERR_OK, "TCP bind");
        /* A raw fixture supplies an established PCB; real tcp_write/output/rexmit
         * retain, combine, and reuse checksum-on-copy state across odd writes. */
        tcp->remote_ip   = remote;
        tcp->remote_port = 8001;
        tcp->state       = ESTABLISHED;
        tcp->snd_wnd = tcp->cwnd = 65535;
        tcp->mss                 = 1460;
        tcp->rcv_nxt             = 1;
        TCP_RMV(&tcp_bound_pcbs, tcp);
        TCP_REG_ACTIVE(tcp);
        uint8_t data[1031];
        fill(data, sizeof(data), 3);
        const uint8_t *payload_data   = carry_case ? carry_input : data;
        const uint16_t payload_length = carry_case ? sizeof(carry_input) : sizeof(data);
        before                        = hook_calls;
        if (carry_case)
        {
            require(tcp_write(tcp, payload_data, payload_length, TCP_WRITE_FLAG_COPY) == ERR_OK,
                    "carry vector TCP write");
        }
        else
        {
            require(tcp_write(tcp, data, 3, TCP_WRITE_FLAG_COPY | TCP_WRITE_FLAG_MORE) == ERR_OK, "odd write one");
            require(tcp_write(tcp, data + 3, 7, TCP_WRITE_FLAG_COPY | TCP_WRITE_FLAG_MORE) == ERR_OK, "odd write two");
            require(tcp_write(tcp, data + 10, 1021, TCP_WRITE_FLAG_COPY) == ERR_OK, "odd write three");
        }
        require(hook_calls >= before + (carry_case ? 1U : 3U), "TCP writes bypassed copy hook");
        before = outputs;
        require(tcp_output(tcp) == ERR_OK && outputs > before, "TCP output");
        unsigned header = 20 + (last_packet[32] >> 4) * 4;
        require(last_length - header == payload_length &&
                    memcmp(last_packet + header, payload_data, payload_length) == 0,
                "TCP payload");
        before = outputs;
        require(tcp_rexmit(tcp) == ERR_OK && tcp_output(tcp) == ERR_OK && outputs > before, "TCP retransmit");
        header = 20 + (last_packet[32] >> 4) * 4;
        require(last_length - header == payload_length &&
                    memcmp(last_packet + header, payload_data, payload_length) == 0,
                "retransmit payload");
        tcp_abort(tcp);
    }

    /* SYN with a valid zero TCP checksum must reach the listener. */
    tcp = tcp_new();
    require(tcp && tcp_bind(tcp, &local, 9002) == ERR_OK, "TCP listener bind");
    struct tcp_pcb *listener = tcp_listen(tcp);
    require(listener != NULL, "TCP listen");
    memset(packet + 20, 0, 22);
    store16(packet + 2, 40);
    packet[9] = IP_PROTO_TCP;
    store16(packet + 10, 0);
    store16(packet + 10, (uint16_t) ~rawOracle(packet, 20));
    store16(packet + 20, 8002);
    store16(packet + 22, 9002);
    packet[32] = 0x50;
    packet[33] = TCP_SYN;
    store16(packet + 34, 4096);
    store16(packet + 26, pseudoOracle(packet + 20, 20, 20, IP_PROTO_TCP, &remote, &local));
    require(pseudoOracle(packet + 20, 20, 20, IP_PROTO_TCP, &remote, &local) == 0, "zero TCP fixture");
    before = outputs;
    inputPacket(&netif, packet, 40);
    require(outputs > before && (last_packet[33] & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK),
            "valid zero TCP rejected");
    const uint32_t unsigned_errors = lwip_stats.tcp.chkerr;
    packet[26] ^= 1;
    before = outputs;
    inputPacket(&netif, packet, 40);
    require(outputs == before && lwip_stats.tcp.chkerr == unsigned_errors + 1, "corrupt TCP not rejected");
    while (tcp_active_pcbs != NULL)
    {
        tcp_abort(tcp_active_pcbs);
    }
    require(tcp_close(listener) == ERR_OK, "listener close");
    netif_remove(&netif);
}

static void runCases(const char *name)
{
    printf("backend: %s\n", name);
    testSpans();
    testChains();
    testProtocols();
    testCarrySpans();
}

int main(void)
{
    /* No library/runtime initializer may precede this call. */
    const uint8_t known[] = {1, 2};
    checkBytes(inet_chksum(known, 2), 0xfefd, "pre-init portable dispatch");
    require(hook_calls == 1, "pre-init hook routing");
    checkSumInit();
    require(lwipTestRuntimeInitialize(), "random runtime init");
    lwip_init();
    runCases("normal startup dispatch");
#ifdef WW_CHECKSUM_TEST_VARIANT
    checksum = checksumDefault;
    runCases("portable");
#if CHECKSUM_SSE3
    if (checkcpu_sse3())
    {
        checksum = checksumSSE3;
        runCases("SSE3");
    }
    else
#endif
    {
        puts("SSE3 unavailable");
    }
#if CHECKSUM_AVX2
    if (checkcpu_avx() && checkcpu_avx2_bmi2())
    {
        checksum = checksumAVX2;
        runCases("AVX2");
    }
    else
#endif
    {
        puts("AVX2 unavailable");
    }
#endif
    wwLwipTestEraseTcpIsnSecret();
    lwipTestRuntimeCleanup();
    puts("lwIP checksum backend tests passed");
    return 0;
}
