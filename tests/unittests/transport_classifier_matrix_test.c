#define kTunnelStateSize kCtpTunnelStateSize
#define kLineStateSize   kCtpLineStateSize
#include "ConnectionToPackets/structure.h"
#undef kLineStateSize
#undef kTunnelStateSize

#define kTunnelStateSize kTcpUdpConnectorTunnelStateSize
#define kLineStateSize   kTcpUdpConnectorLineStateSize
#include "TcpUdpConnector/structure.h"
#undef kLineStateSize
#undef kTunnelStateSize

#include "lwip/prot/ip4.h"

typedef struct classifier_case_s
{
    const char       *name;
    address_context_t context;
    uint8_t           expected_protocol;
} classifier_case_t;

#define FLAGS(tcp, udp, icmp, packet)                                                                                  \
    {.proto_tcp = (tcp), .proto_udp = (udp), .proto_icmp = (icmp), .proto_packet = (packet)}

static const classifier_case_t kCases[] = {
    {"absent", FLAGS(0, 0, 0, 0), 0},
    {"tcp", FLAGS(1, 0, 0, 0), IP_PROTO_TCP},
    {"udp", FLAGS(0, 1, 0, 0), IP_PROTO_UDP},
    {"icmp", FLAGS(0, 0, 1, 0), 0},
    {"packet", FLAGS(0, 0, 0, 1), 0},
    {"tcp+udp", FLAGS(1, 1, 0, 0), 0},
    {"tcp+icmp", FLAGS(1, 0, 1, 0), 0},
    {"tcp+packet", FLAGS(1, 0, 0, 1), 0},
    {"udp+icmp", FLAGS(0, 1, 1, 0), 0},
    {"udp+packet", FLAGS(0, 1, 0, 1), 0},
    {"icmp+packet", FLAGS(0, 0, 1, 1), 0},
    {"tcp+udp+icmp", FLAGS(1, 1, 1, 0), 0},
    {"tcp+udp+packet", FLAGS(1, 1, 0, 1), 0},
    {"tcp+icmp+packet", FLAGS(1, 0, 1, 1), 0},
    {"udp+icmp+packet", FLAGS(0, 1, 1, 1), 0},
    {"all", FLAGS(1, 1, 1, 1), 0},
};

static void fail(const classifier_case_t *dest, const classifier_case_t *source, const char *node, const char *message)
{
    fprintf(stderr,
            "transport classifier failed for %s destination=%s source=%s: %s\n",
            node,
            dest->name,
            source->name,
            message);
    exit(1);
}

int main(void)
{
    tunnel_t *selector = memoryAllocateZero(sizeof(tunnel_t) + sizeof(tcpudpconnector_tstate_t));
    tunnel_t *tcp      = memoryAllocateZero(sizeof(tunnel_t) + 4096);
    tunnel_t *udp      = memoryAllocateZero(sizeof(tunnel_t) + 4096);
    if (selector == NULL || tcp == NULL || udp == NULL)
    {
        fprintf(stderr, "transport classifier fixture allocation failed\n");
        return 1;
    }

    tcpudpconnector_tstate_t *state = tunnelGetState(selector);
    state->tcp_connector            = tcp;
    state->udp_connector            = udp;

    for (size_t dest_index = 0; dest_index < ARRAY_SIZE(kCases); ++dest_index)
    {
        for (size_t source_index = 0; source_index < ARRAY_SIZE(kCases); ++source_index)
        {
            const classifier_case_t *dest   = &kCases[dest_index];
            const classifier_case_t *source = &kCases[source_index];
            line_t                   line   = {0};
            line.routing_context.dest_ctx   = dest->context;
            line.routing_context.src_ctx    = source->context;

            /* A nonempty destination always wins, including unsupported combinations. */
            const uint8_t expected = dest_index == 0 ? source->expected_protocol : dest->expected_protocol;

            uint8_t protocol = UINT8_C(0xA5);
            bool    accepted = ctpSelectProtocol(NULL, &line, &protocol);
            if (accepted != (expected != 0))
            {
                fail(dest, source, "ConnectionToPackets", "accept/reject result differed");
            }
            if (accepted && protocol != expected)
            {
                fail(dest, source, "ConnectionToPackets", "selected protocol differed");
            }
            if (! accepted && protocol != UINT8_C(0xA5))
            {
                fail(dest, source, "ConnectionToPackets", "rejection modified the output protocol");
            }

            tunnel_t *selected = tcpudpconnectorSelectUpStreamTunnel(selector, &line);
            tunnel_t *wanted   = expected == IP_PROTO_TCP ? tcp : (expected == IP_PROTO_UDP ? udp : NULL);
            if (selected != wanted)
            {
                fail(dest, source, "TcpUdpConnector", "selected connector differed");
            }
        }
    }

    memoryFree(udp);
    memoryFree(tcp);
    memoryFree(selector);
    puts("transport classifier matrix tests passed");
    return 0;
}
