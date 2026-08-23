#include "ww_lwip.h"
#include "wwapi.h"

typedef struct input_pbuf_s
{
    struct pbuf_custom custom;
    uint8_t            bytes[20 + UDP_HLEN + 64];
    uint32_t           free_count;
} input_pbuf_t;

typedef struct udp_flow_probe_s
{
    ip_addr_t       source;
    ip_addr_t       destination;
    uint16_t        source_port;
    uint16_t        destination_port;
    const uint8_t  *payload;
    uint16_t        payload_length;
    struct udp_pcb *child;
    uint32_t        accept_count;
    uint32_t        receive_count;
} udp_flow_probe_t;

typedef struct udp_dispatch_fixture_s
{
    struct netif     netif;
    struct udp_pcb  *listener;
    udp_flow_probe_t flows[2];
    const char      *failure;
    atomic_bool      completed;
} udp_dispatch_fixture_t;

static atomic_bool tcpip_initialized;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "lwip_pretend_udp_dispatch_test: %s\n", message);
        exit(1);
    }
}

static void fixtureFail(udp_dispatch_fixture_t *fixture, const char *message)
{
    if (fixture->failure == NULL)
    {
        fixture->failure = message;
    }
}

static bool fixtureExpect(udp_dispatch_fixture_t *fixture, bool condition, const char *message)
{
    if (! condition)
    {
        fixtureFail(fixture, message);
        return false;
    }
    return true;
}

static void tcpipInitialized(void *argument)
{
    discard argument;
    atomicStoreExplicit(&tcpip_initialized, true, memory_order_release);
}

static void inputPbufFree(struct pbuf *p)
{
    input_pbuf_t *input = (input_pbuf_t *) ((uint8_t *) p - offsetof(input_pbuf_t, custom.pbuf));
    ++input->free_count;
}

static err_t pretendNetifInit(struct netif *netif)
{
    netif->name[0] = 'p';
    netif->name[1] = 'u';
    netif->mtu     = 1500;
    netif->flags   = NETIF_FLAG_PRETEND;
    return ERR_OK;
}

static udp_flow_probe_t *findFlowForChild(udp_dispatch_fixture_t *fixture, const struct udp_pcb *child)
{
    for (size_t i = 0; i < ARRAY_SIZE(fixture->flows); ++i)
    {
        udp_flow_probe_t *flow = &fixture->flows[i];
        if (child->remote_port == flow->source_port && child->local_port == flow->destination_port &&
            ip_addr_cmp(&child->remote_ip, &flow->source) && ip_addr_cmp(&child->local_ip, &flow->destination))
        {
            return flow;
        }
    }
    return NULL;
}

static udp_flow_probe_t *findFlowForReceivedPacket(udp_dispatch_fixture_t *fixture, const struct udp_pcb *child,
                                                   const ip_addr_t *source, uint16_t source_port)
{
    udp_flow_probe_t *flow = findFlowForChild(fixture, child);
    if (flow != NULL && source_port == flow->source_port && ip_addr_cmp(source, &flow->source))
    {
        return flow;
    }
    return NULL;
}

static void discardUnexpectedChildDatagram(void *argument, struct udp_pcb *child, struct pbuf *p,
                                           const ip_addr_t *source, u16_t source_port)
{
    discard child;
    discard source;
    discard source_port;

    fixtureFail(argument, "listener scan could not install the connected child receive callback");
    if (p != NULL)
    {
        pbuf_free(p);
    }
}

static void receiveChildDatagram(void *argument, struct udp_pcb *child, struct pbuf *p, const ip_addr_t *source,
                                 u16_t source_port)
{
    udp_dispatch_fixture_t *fixture = argument;
    udp_flow_probe_t       *flow =
        child != NULL && source != NULL ? findFlowForReceivedPacket(fixture, child, source, source_port) : NULL;

    if (flow == NULL)
    {
        fixtureFail(fixture, "received datagram did not match a connected child tuple");
    }
    else
    {
        uint8_t received[64];

        ++flow->receive_count;
        if (p == NULL)
        {
            fixtureFail(fixture, "connected child received a NULL datagram");
        }
        else if (p->tot_len != flow->payload_length || p->tot_len > sizeof(received) ||
                 pbuf_copy_partial(p, received, p->tot_len, 0) != p->tot_len ||
                 ! memoryEqual(received, flow->payload, flow->payload_length))
        {
            fixtureFail(fixture, "connected child did not receive exactly the UDP application payload");
        }
    }

    if (p != NULL)
    {
        pbuf_free(p);
    }
}

static void acceptPretendChild(void *argument, struct udp_pcb *child, struct pbuf *p, const ip_addr_t *address,
                               u16_t port)
{
    discard address;
    discard port;

    udp_dispatch_fixture_t *fixture = argument;
    if (child == fixture->listener)
    {
        fixtureFail(fixture, "wildcard listener reached the ordinary UDP callback path");
        if (p != NULL)
        {
            pbuf_free(p);
        }
        return;
    }

    udp_flow_probe_t *flow = child != NULL ? findFlowForChild(fixture, child) : NULL;
    if (flow == NULL)
    {
        fixtureFail(fixture, "listener scan did not allocate the expected connected child");
        if (child != NULL)
        {
            udp_recv(child, discardUnexpectedChildDatagram, fixture);
        }
        return;
    }
    if (flow->child != NULL)
    {
        fixtureFail(fixture, "listener scan created more than one child for one tuple");
        udp_recv(child, discardUnexpectedChildDatagram, fixture);
        return;
    }

    ++flow->accept_count;
    flow->child = child;
    if (! fixtureExpect(
            fixture, (child->flags & UDP_FLAGS_CONNECTED) != 0, "listener scan created an unconnected child") ||
        ! fixtureExpect(fixture,
                        udp_bind_netif(child, &fixture->netif) == ERR_OK,
                        "could not retain the child on the pretend netif"))
    {
        udp_recv(child, discardUnexpectedChildDatagram, fixture);
        return;
    }

    /* The listener scan still owns p and will redispatch it through this callback. */
    udp_recv(child, receiveChildDatagram, fixture);
}

static void writeIpv4Checksum(uint8_t *packet)
{
    uint32_t sum = 0;

    PUT_BE16(packet + 10, 0);
    for (uint32_t offset = 0; offset < 20; offset += 2)
    {
        sum += GET_BE16(packet + offset);
    }
    while ((sum >> 16U) != 0)
    {
        sum = (sum & UINT32_C(0xFFFF)) + (sum >> 16U);
    }
    PUT_BE16(packet + 10, (uint16_t) ~sum);
}

static bool injectIpv4UdpDatagram(udp_dispatch_fixture_t *fixture, const udp_flow_probe_t *flow,
                                  uint16_t identification)
{
    input_pbuf_t   input         = {0};
    const uint16_t packet_length = (uint16_t) (20U + UDP_HLEN + flow->payload_length);

    input.custom.custom_free_function = inputPbufFree;
    input.bytes[0]                    = 0x45;
    input.bytes[8]                    = 64;
    input.bytes[9]                    = IP_PROTO_UDP;
    PUT_BE16(input.bytes + 2, packet_length);
    PUT_BE16(input.bytes + 4, identification);
    memoryCopy(input.bytes + 12, &ip_2_ip4(&flow->source)->addr, sizeof(ip_2_ip4(&flow->source)->addr));
    memoryCopy(input.bytes + 16, &ip_2_ip4(&flow->destination)->addr, sizeof(ip_2_ip4(&flow->destination)->addr));
    PUT_BE16(input.bytes + 20, flow->source_port);
    PUT_BE16(input.bytes + 22, flow->destination_port);
    PUT_BE16(input.bytes + 24, (uint16_t) (UDP_HLEN + flow->payload_length));
    PUT_BE16(input.bytes + 26, 0);
    memoryCopy(input.bytes + 20 + UDP_HLEN, flow->payload, flow->payload_length);
    writeIpv4Checksum(input.bytes);

    struct pbuf *p = pbuf_alloced_custom(PBUF_RAW, packet_length, PBUF_REF, &input.custom, input.bytes, packet_length);
    if (! fixtureExpect(fixture, p != NULL, "failed to allocate a custom ingress pbuf"))
    {
        return false;
    }

    if (! fixtureExpect(fixture, ip_input(p, &fixture->netif) == ERR_OK, "IPv4 input rejected a valid UDP datagram"))
    {
        return false;
    }
    return fixtureExpect(fixture, input.free_count == 1, "ingress pbuf was not released exactly once");
}

static bool setupFixture(udp_dispatch_fixture_t *fixture)
{
    ip4_addr_t local;
    ip4_addr_t netmask;
    ip4_addr_t gateway;

    IP4_ADDR(&local, 192, 0, 2, 1);
    IP4_ADDR(&netmask, 255, 255, 255, 0);
    IP4_ADDR(&gateway, 0, 0, 0, 0);
    if (! fixtureExpect(fixture,
                        netif_add(&fixture->netif, &local, &netmask, &gateway, NULL, pretendNetifInit, ip_input) !=
                            NULL,
                        "failed to add the pretend netif"))
    {
        return false;
    }
    netif_set_up(&fixture->netif);
    netif_set_link_up(&fixture->netif);

    fixture->listener = udp_new_ip_type(IPADDR_TYPE_ANY);
    if (! fixtureExpect(fixture, fixture->listener != NULL, "failed to allocate the wildcard pretend listener") ||
        ! fixtureExpect(fixture,
                        udp_bind_netif(fixture->listener, &fixture->netif) == ERR_OK,
                        "failed to bind the listener to the pretend netif") ||
        ! fixtureExpect(
            fixture, udp_bind(fixture->listener, NULL, 0) == ERR_OK, "failed to bind the wildcard pretend listener"))
    {
        return false;
    }

    udp_recv(fixture->listener, acceptPretendChild, fixture);
    return fixtureExpect(fixture,
                         fixture->listener->local_port == 0,
                         "pretend listener unexpectedly acquired an ephemeral port") &&
           fixtureExpect(fixture,
                         IP_IS_ANY_TYPE_VAL(fixture->listener->local_ip),
                         "pretend listener did not retain its ANY local address") &&
           fixtureExpect(fixture,
                         (fixture->listener->flags & UDP_FLAGS_CONNECTED) == 0,
                         "pretend listener unexpectedly became connected");
}

static void cleanupFixture(udp_dispatch_fixture_t *fixture)
{
    for (size_t i = 0; i < ARRAY_SIZE(fixture->flows); ++i)
    {
        if (fixture->flows[i].child != NULL)
        {
            udp_recv(fixture->flows[i].child, NULL, NULL);
            udp_remove(fixture->flows[i].child);
            fixture->flows[i].child = NULL;
        }
    }
    if (fixture->listener != NULL)
    {
        udp_recv(fixture->listener, NULL, NULL);
        udp_remove(fixture->listener);
        fixture->listener = NULL;
    }
    fixtureExpect(fixture, udp_pcbs == NULL, "fixture cleanup left UDP PCBs attached");
    if (fixture->netif.ww_generation != 0)
    {
        const u8_t netif_index = netif_get_index(&fixture->netif);

        netif_remove(&fixture->netif);
        fixtureExpect(fixture, netif_get_by_index(netif_index) == NULL, "fixture cleanup left the netif attached");
        fixture->netif.ww_generation = 0;
    }
}

static bool verifyFixture(udp_dispatch_fixture_t *fixture)
{
    if (! fixtureExpect(
            fixture, fixture->listener->recv == acceptPretendChild, "wildcard listener callback was replaced") ||
        ! fixtureExpect(
            fixture, fixture->listener->recv_arg == fixture, "wildcard listener callback argument changed") ||
        ! fixtureExpect(fixture, fixture->listener->local_port == 0, "wildcard listener local port was rewritten") ||
        ! fixtureExpect(fixture,
                        IP_IS_ANY_TYPE_VAL(fixture->listener->local_ip),
                        "wildcard listener local address was rewritten") ||
        ! fixtureExpect(
            fixture, (fixture->listener->flags & UDP_FLAGS_CONNECTED) == 0, "wildcard listener became connected"))
    {
        return false;
    }

    for (size_t i = 0; i < ARRAY_SIZE(fixture->flows); ++i)
    {
        udp_flow_probe_t *flow = &fixture->flows[i];
        if (! fixtureExpect(fixture, flow->accept_count == 1, "fresh UDP tuple was not accepted exactly once") ||
            ! fixtureExpect(fixture, flow->receive_count == 1, "fresh UDP tuple was not delivered exactly once") ||
            ! fixtureExpect(fixture, flow->child != NULL, "listener scan did not retain its connected child"))
        {
            return false;
        }
    }
    return fixtureExpect(
        fixture, fixture->flows[0].child != fixture->flows[1].child, "separate UDP tuples shared one connected child");
}

static void runFixture(void *argument)
{
    static const uint8_t    first_payload[]  = "port-zero";
    static const uint8_t    second_payload[] = "second-flow";
    udp_dispatch_fixture_t *fixture          = argument;

    IP4_ADDR(ip_2_ip4(&fixture->flows[0].source), 198, 51, 100, 20);
    IP_SET_TYPE(&fixture->flows[0].source, IPADDR_TYPE_V4);
    IP4_ADDR(ip_2_ip4(&fixture->flows[0].destination), 203, 0, 113, 30);
    IP_SET_TYPE(&fixture->flows[0].destination, IPADDR_TYPE_V4);
    fixture->flows[0].source_port      = 41000;
    fixture->flows[0].destination_port = 0;
    fixture->flows[0].payload          = first_payload;
    fixture->flows[0].payload_length   = sizeof(first_payload) - 1U;

    IP4_ADDR(ip_2_ip4(&fixture->flows[1].source), 198, 51, 100, 21);
    IP_SET_TYPE(&fixture->flows[1].source, IPADDR_TYPE_V4);
    IP4_ADDR(ip_2_ip4(&fixture->flows[1].destination), 203, 0, 113, 31);
    IP_SET_TYPE(&fixture->flows[1].destination, IPADDR_TYPE_V4);
    fixture->flows[1].source_port      = 41001;
    fixture->flows[1].destination_port = 53000;
    fixture->flows[1].payload          = second_payload;
    fixture->flows[1].payload_length   = sizeof(second_payload) - 1U;

    if (setupFixture(fixture))
    {
        discard injectIpv4UdpDatagram(fixture, &fixture->flows[0], 1);
        if (fixture->failure == NULL)
        {
            discard injectIpv4UdpDatagram(fixture, &fixture->flows[1], 2);
        }
        if (fixture->failure == NULL)
        {
            discard verifyFixture(fixture);
        }
    }

    cleanupFixture(fixture);
    atomicStoreExplicit(&fixture->completed, true, memory_order_release);
}

int main(void)
{
    udp_dispatch_fixture_t fixture = {0};

    atomic_init(&tcpip_initialized, false);
    atomic_init(&fixture.completed, false);
    tcpip_init(tcpipInitialized, NULL);
    while (! atomicLoadExplicit(&tcpip_initialized, memory_order_acquire))
    {
        YIELD_THREAD();
    }

    require(tcpip_callback(runFixture, &fixture) == ERR_OK, "failed to schedule the lwIP fixture");
    while (! atomicLoadExplicit(&fixture.completed, memory_order_acquire))
    {
        YIELD_THREAD();
    }

    require(wwLwipShutdown(), "failed to shut down the lwIP thread");
    require(fixture.failure == NULL, fixture.failure != NULL ? fixture.failure : "fixture failed without a diagnostic");
    puts("lwIP pretend UDP dispatch tests passed");
    return 0;
}
