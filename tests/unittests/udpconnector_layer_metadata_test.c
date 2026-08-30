/*
 * Regression coverage for UdpConnector's public layer metadata.
 *
 * The test uses the real node descriptors so it fails if UdpConnector is made
 * packet-compatible again or if PacketsToStream stops providing the explicit
 * Layer-3 to Layer-4 boundary.
 */

#include "PacketSender/interface.h"
#include "PacketsToStream/interface.h"
#include "UdpConnector/interface.h"

#include "net/node_layer_solver.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void bindTunnels(tunnel_t *from, tunnel_t *to)
{
    from->next = to;
    to->prev   = from;
}

static void releaseNodeTypes(node_t *sender, node_t *bridge, node_t *connector)
{
    memoryFree(sender->type);
    if (bridge != NULL)
    {
        memoryFree(bridge->type);
    }
    memoryFree(connector->type);
}

static void testDirectPacketSenderPlacementIsRejected(void)
{
    node_t sender    = nodePacketSenderGet();
    node_t connector = nodeUdpConnectorGet();

    sender.name    = (char *) "packet-sender";
    connector.name = (char *) "udp-connector";

    require(connector.layer_group == kNodeLayer4, "UdpConnector does not advertise Layer 4");
    require(connector.layer_group_prev_node == kNodeLayer4, "UdpConnector does not require a Layer-4 previous node");
    require(connector.layer_group_next_node == kNodeLayerNone, "UdpConnector unexpectedly permits a following node");

    tunnel_t sender_tunnel    = {.node = &sender};
    tunnel_t connector_tunnel = {.node = &connector};
    bindTunnels(&sender_tunnel, &connector_tunnel);

    tunnel_chain_t chain = {0};
    tunnelarrayInsert(&chain.tunnels, &sender_tunnel);
    tunnelarrayInsert(&chain.tunnels, &connector_tunnel);

    node_layer_solver_status_t status = {0};
    require(! nodeLayerSolveChain(&chain, &status),
            "PacketSender -> UdpConnector unexpectedly solved without a packet/stream bridge");
    require(status.code == kNodeLayerSolverErrConflict,
            "direct PacketSender -> UdpConnector failed for an unexpected reason");

    releaseNodeTypes(&sender, NULL, &connector);
}

static void testPacketsToStreamPlacementIsAccepted(void)
{
    node_t sender    = nodePacketSenderGet();
    node_t bridge    = nodePacketsToStreamGet();
    node_t connector = nodeUdpConnectorGet();

    sender.name    = (char *) "packet-sender";
    bridge.name    = (char *) "packets-to-stream";
    connector.name = (char *) "udp-connector";

    tunnel_t sender_tunnel    = {.node = &sender};
    tunnel_t bridge_tunnel    = {.node = &bridge};
    tunnel_t connector_tunnel = {.node = &connector};
    bindTunnels(&sender_tunnel, &bridge_tunnel);
    bindTunnels(&bridge_tunnel, &connector_tunnel);

    tunnel_chain_t chain = {0};
    tunnelarrayInsert(&chain.tunnels, &sender_tunnel);
    tunnelarrayInsert(&chain.tunnels, &bridge_tunnel);
    tunnelarrayInsert(&chain.tunnels, &connector_tunnel);

    node_layer_solver_status_t status = {0};
    require(nodeLayerSolveChain(&chain, &status), "PacketSender -> PacketsToStream -> UdpConnector was rejected");
    require(chain.contains_packet_node, "bridged chain was not classified as containing a packet side");
    require(chain.resolved_next_layer[0] == kLayerDomainL3, "PacketSender output did not resolve to Layer 3");
    require(chain.resolved_prev_layer[1] == kLayerDomainL3, "PacketsToStream input did not resolve to Layer 3");
    require(chain.resolved_next_layer[1] == kLayerDomainL4, "PacketsToStream output did not resolve to Layer 4");
    require(chain.resolved_prev_layer[2] == kLayerDomainL4, "UdpConnector input did not resolve to Layer 4");

    releaseNodeTypes(&sender, &bridge, &connector);
}

int main(void)
{
    testDirectPacketSenderPlacementIsRejected();
    testPacketsToStreamPlacementIsAccepted();

    printf("UDP CONNECTOR LAYER METADATA TESTS PASSED\n");
    return 0;
}
