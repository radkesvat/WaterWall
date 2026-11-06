/*
 * Covers: timestamp parsing and TCP send progress at small MSS/window boundaries.
 * Setup: a private timestamps-enabled raw engine, real IPv4/TCP handshakes and a recording netif.
 * Checks: exact high-bit timestamp echoes; bounded, nonempty segments with ordered payload bytes;
 * tiny advertised MSS/window values with and without timestamp negotiation; complete ACK cleanup.
 * Limits: this enables timestamps only in the private fixture, not the production configuration.
 * CTest: waterwall.lwip_timestamp_boundaries_unit (Debug, Release and ASan/UBSan).
 */
#include "fixtures/lwip/lwip_engine_test_runtime.h"
#include "lwip/ip.h"
#include "lwip/netif.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/stats.h"

static const uint8_t payload[] = {0x5a, 0xc3, 0x17, 0xe9};

typedef struct
{
    ww_lwip_engine_t *engine, *previous;
    struct netif      netif;
    struct tcp_pcb   *pcb;
    uint32_t          peer_next, output_next, last_ack, last_echo;
    uint16_t          peer_mss, peer_window;
    uint8_t           last_flags;
    unsigned          outputs, sent, received, maximum_payload;
    bool              timestamps, last_had_timestamp;
} fixture_t;

static fixture_t fixture;

static void put16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t) (value >> 8);
    p[1] = (uint8_t) value;
}

static void put32(uint8_t *p, uint32_t value)
{
    put16(p, (uint16_t) (value >> 16));
    put16(p + 2, (uint16_t) value);
}

static uint16_t get16(const uint8_t *p)
{
    return (uint16_t) (((uint16_t) p[0] << 8) | p[1]);
}

static uint32_t get32(const uint8_t *p)
{
    return ((uint32_t) get16(p) << 16) | get16(p + 2);
}

static err_t output(struct netif *netif, struct pbuf *packet, const ip4_addr_t *destination)
{
    (void) destination;
    fixture_t *f = netif->state;
    uint8_t    bytes[80];
    CHECK(f == &fixture && wwLwipEngineCurrent() == f->engine);
    CHECK(packet->tot_len >= 40 && packet->tot_len <= sizeof(bytes));
    CHECK(pbuf_copy_partial(packet, bytes, packet->tot_len, 0) == packet->tot_len);
    CHECK(bytes[0] == 0x45 && bytes[9] == 6 && get16(bytes + 2) == packet->tot_len);
    const unsigned header_length = 20U + (bytes[32] >> 4) * 4U;
    CHECK(header_length >= 40 && header_length <= packet->tot_len);
    ++f->outputs;
    f->last_ack           = get32(bytes + 28);
    f->last_flags         = bytes[33];
    f->last_had_timestamp = false;
    for (unsigned i = 40; i < header_length && bytes[i] != 0;)
    {
        if (bytes[i] == 1)
        {
            ++i;
            continue;
        }
        CHECK(i + 1 < header_length && bytes[i + 1] >= 2 && i + bytes[i + 1] <= header_length);
        if (bytes[i] == 8)
        {
            CHECK(bytes[i + 1] == 10 && ! f->last_had_timestamp);
            f->last_had_timestamp = true;
            f->last_echo          = get32(bytes + i + 6);
        }
        i += bytes[i + 1];
    }
    const unsigned length = packet->tot_len - header_length;
    if (length != 0)
    {
        CHECK((f->last_flags & (TCP_ACK | TCP_SYN | TCP_RST)) == TCP_ACK);
        CHECK(f->last_had_timestamp == f->timestamps);
        CHECK(length <= f->maximum_payload && f->sent + length <= sizeof(payload));
        CHECK(get32(bytes + 24) == f->output_next);
        CHECK(memcmp(bytes + header_length, payload + f->sent, length) == 0);
        f->sent += length;
        f->output_next += length;
    }
    return ERR_OK;
}

static err_t initNetif(struct netif *netif)
{
    netif->name[0] = 't';
    netif->name[1] = 'b';
    netif->mtu     = 1500;
    netif->output  = output;
    return ERR_OK;
}

static err_t receive(void *argument, struct tcp_pcb *pcb, struct pbuf *packet, err_t error)
{
    fixture_t *f = argument;
    CHECK(pcb == f->pcb && packet != NULL && error == ERR_OK);
    CHECK(packet->tot_len == 1 && pbuf_get_at(packet, 0) == 0x5a);
    f->received += packet->tot_len;
    tcp_recved(pcb, packet->tot_len);
    pbuf_free(packet);
    return ERR_OK;
}

static err_t accepted(void *argument, struct tcp_pcb *pcb, err_t error)
{
    fixture_t *f = argument;
    CHECK(pcb == f->pcb && error == ERR_OK);
    tcp_recv(pcb, receive);
    return ERR_OK;
}

static void inject(fixture_t *f, uint8_t flags, uint16_t data_length, uint32_t timestamp)
{
    CHECK(data_length <= 1 && f->pcb != NULL);
    const uint16_t options    = (uint16_t) (((flags & TCP_SYN) != 0 ? 4 : 0) + (f->timestamps ? 12 : 0));
    const uint16_t length     = (uint16_t) (40 + options + data_length);
    uint8_t        bytes[57]  = {0x45};
    uint8_t        pseudo[49] = {0};
    put16(bytes + 2, length);
    bytes[8]  = 64;
    bytes[9]  = 6;
    bytes[12] = 10;
    bytes[15] = 2;
    bytes[16] = 10;
    bytes[19] = 1;
    put16(bytes + 20, 80);
    put16(bytes + 22, f->pcb->local_port);
    put32(bytes + 24, f->peer_next);
    put32(bytes + 28, (flags & TCP_ACK) != 0 ? f->pcb->snd_nxt : 0);
    bytes[32] = (uint8_t) ((5 + options / 4) << 4);
    bytes[33] = flags;
    put16(bytes + 34, f->peer_window);
    unsigned option_offset = 40;
    if ((flags & TCP_SYN) != 0)
    {
        bytes[40] = 2;
        bytes[41] = 4;
        put16(bytes + 42, f->peer_mss);
        option_offset += 4;
    }
    if (f->timestamps)
    {
        bytes[option_offset]     = 1;
        bytes[option_offset + 1] = 1;
        bytes[option_offset + 2] = 8;
        bytes[option_offset + 3] = 10;
        put32(bytes + option_offset + 4, timestamp);
    }
    memset(bytes + 40 + options, 0x5a, data_length);
    memcpy(pseudo, bytes + 12, 8);
    pseudo[9] = 6;
    put16(pseudo + 10, (uint16_t) (length - 20));
    memcpy(pseudo + 12, bytes + 20, length - 20);
    uint16_t checksum = (uint16_t) ~wwLwipChecksum(pseudo, length - 8);
    memcpy(bytes + 36, &checksum, sizeof(checksum));
    checksum = (uint16_t) ~wwLwipChecksum(bytes, 20);
    memcpy(bytes + 10, &checksum, sizeof(checksum));
    struct pbuf *packet = pbuf_alloc(PBUF_RAW, length, PBUF_RAM);
    CHECK(packet != NULL && pbuf_take(packet, bytes, length) == ERR_OK);
    CHECK(wwLwipEngineInput(f->engine, packet, &f->netif) == ERR_OK);
}

static fixture_t *start(uint16_t mss, uint16_t window, bool timestamps, uint32_t timestamp)
{
    fixture_t *f = &fixture;
    memset(f, 0, sizeof(*f));
    f->peer_next   = 100;
    f->peer_mss    = mss;
    f->peer_window = window;
    f->timestamps  = timestamps;
    owner          = 0;
    owner_loop     = (struct wloop_s *) &f->netif;
    f->engine      = wwLwipEngineCreate((uint8_t) owner, (struct wloop_s *) owner_loop);
    CHECK(f->engine != NULL && wwLwipEngineEnter(f->engine, &f->previous));
    ip4_addr_t address, mask, gateway;
    IP4_ADDR(&address, 10, 0, 0, 1);
    IP4_ADDR(&mask, 255, 255, 255, 0);
    ip4_addr_set_zero(&gateway);
    CHECK(netif_add(&f->netif, &address, &mask, &gateway, f, initNetif, ip_input) != NULL);
    netif_set_up(&f->netif);
    netif_set_link_up(&f->netif);
    f->pcb = tcp_new();
    CHECK(f->pcb != NULL && tcp_bind_netif(f->pcb, &f->netif) == ERR_OK);
    CHECK(tcp_bind(f->pcb, IP_ADDR_ANY, 1234) == ERR_OK);
    tcp_arg(f->pcb, f);
    struct tcp_pcb *listener = tcp_listen(f->pcb);
    CHECK(listener != NULL);
    tcp_accept(listener, accepted);
    f->pcb = listener;
    inject(f, TCP_SYN, 0, timestamp);
    f->pcb = tcp_active_pcbs;
    CHECK(f->pcb != NULL && f->pcb->state == SYN_RCVD);
    CHECK(f->outputs == 1 && f->last_flags == (TCP_SYN | TCP_ACK));
    CHECK(f->last_had_timestamp == timestamps && (! timestamps || f->last_echo == timestamp));
    ++f->peer_next;
    inject(f, TCP_ACK, 0, timestamp);
    CHECK(f->pcb->state == ESTABLISHED && f->pcb->mss == mss && f->pcb->snd_wnd_max == window);
    CHECK(((f->pcb->flags & TF_TIMESTAMP) != 0) == timestamps);
    CHECK(tcp_close(listener) == ERR_OK);
    tcp_nagle_disable(f->pcb);
    return f;
}

static void stop(fixture_t *f)
{
    tcp_abort(f->pcb);
    f->pcb = NULL;
    wwLwipEngineLeave(f->engine, f->previous);
    wwLwipEngineDestroy(f->engine);
    CHECK(wwLwipEngineCurrent() == NULL);
    CHECK(wwLwipSharedStats()->memp[MEMP_TCP_SEG]->used == 0 && wwLwipSharedStats()->mem.used == 0);
}

static void timestampEcho(uint32_t timestamp)
{
    fixture_t *f = start(1460, UINT16_MAX, true, timestamp);
    f->outputs   = 0;
    inject(f, TCP_ACK, 1, timestamp + 1U);
    ++f->peer_next;
    tcp_ack_now(f->pcb);
    CHECK(tcp_output(f->pcb) == ERR_OK);
    CHECK(f->received == 1 && f->outputs >= 1 && f->last_ack == f->peer_next);
    CHECK(f->last_had_timestamp && f->last_echo == timestamp + 1U);
    stop(f);
}

static void sendPayload(uint16_t mss, uint16_t window, bool timestamps, unsigned maximum_payload)
{
    fixture_t *f       = start(mss, window, timestamps, 500);
    f->maximum_payload = maximum_payload;
    f->output_next     = f->pcb->snd_nxt;
    f->outputs         = 0;
    CHECK(tcp_write(f->pcb, payload, sizeof(payload), TCP_WRITE_FLAG_COPY) == ERR_OK);
    unsigned segments = 0, queued = 0;
    for (const struct tcp_seg *segment = f->pcb->unsent; segment != NULL; segment = segment->next)
    {
        CHECK(++segments <= sizeof(payload));
        CHECK(segment->len > 0 && segment->len <= maximum_payload);
        queued += segment->len;
    }
    CHECK(queued == sizeof(payload));
    CHECK(tcp_output(f->pcb) == ERR_OK);
    CHECK(f->sent == sizeof(payload) && f->outputs == segments);
    inject(f, TCP_ACK, 0, 501);
    CHECK(f->pcb->unsent == NULL && f->pcb->unacked == NULL && f->pcb->snd_queuelen == 0);
    stop(f);
}

int main(void)
{
    CHECK(LWIP_TCP_TIMESTAMPS == 1);
    wwLwipEngineSharedInit();
    static const uint32_t timestamps[] = {
        UINT32_C(0x00000080), 500, UINT32_C(0x80000000), UINT32_C(0x89abcdef), UINT32_MAX};
    testCaseSet("timestamp bytes with their high bit set retain the exact wire value");
    for (unsigned i = 0; i < sizeof(timestamps) / sizeof(timestamps[0]); ++i)
        timestampEcho(timestamps[i]);
    static const struct
    {
        const char *name;
        uint16_t    mss, window;
        bool        timestamps;
        unsigned    maximum_payload;
    } cases[] = {{"MSS 11 with timestamps", 11, UINT16_MAX, true, 1},
                 {"MSS 12 with timestamps", 12, UINT16_MAX, true, 1},
                 {"MSS 13 with timestamps", 13, UINT16_MAX, true, 1},
                 {"MSS 11 without timestamps", 11, UINT16_MAX, false, 4},
                 {"MSS 12 without timestamps", 12, UINT16_MAX, false, 4},
                 {"MSS 13 without timestamps", 13, UINT16_MAX, false, 4},
                 {"window 24 with timestamps", 1460, 24, true, 1},
                 {"window 24 without timestamps", 1460, 24, false, 4},
                 {"ordinary MSS and window with timestamps", 1460, UINT16_MAX, true, 4},
                 {"ordinary MSS and window without timestamps", 1460, UINT16_MAX, false, 4}};
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        testCaseSet(cases[i].name);
        sendPayload(cases[i].mss, cases[i].window, cases[i].timestamps, cases[i].maximum_payload);
    }
    wwLwipEngineSharedCleanup();
    puts("timestamp values and small-segment send progress remain correct");
    return 0;
}
