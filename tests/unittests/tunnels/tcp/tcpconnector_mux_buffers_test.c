/*
 * Covers: tcpconnector mux buffers; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: testBuffers
 * Checks: Assertion labels include: incorrect connector send-buffer size; incorrect connector
 * receive-buffer size; incorrect destination send-buffer size; incorrect destination receive-buffer size
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.tcpconnector_mux_buffers_unit
 */
#include "TcpConnector/structure.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static void testBuffers(bool tune_enabled, bool client, bool server, unsigned send_option, unsigned recv_option,
                        int default_size)
{
    GSTATE.tcp_tune_enabled = tune_enabled;
    /* Zero is omitted; the remaining values model explicit false, true and an integer. */
    const int      configured_sizes[]  = {0, 0, kDefaultLargeSocketBufferSize, 131072};
    const int      destination_sizes[] = {0, 0, kDefaultLargeSocketBufferSize, 65536};
    node_t         node                = {.type = (char *) "TcpConnector"};
    tunnel_chain_t chain               = {.mux_client_tunnel_present = client, .mux_server_tunnel_present = server};
    tunnel_t      *t                   = tunnelCreate(&node, sizeof(tcpconnector_tstate_t), 0);
    require(t != NULL, "failed to allocate connector fixture");
    t->chain                     = &chain;
    tcpconnector_tstate_t *state = tunnelGetState(t);
    state->send_buffer_size      = configured_sizes[send_option];
    state->recv_buffer_size      = configured_sizes[recv_option];
    state->send_buffer_size_set  = send_option != 0;
    state->recv_buffer_size_set  = recv_option != 0;

    tcpconnector_destination_t destinations[16] = {0};
    for (unsigned i = 0; i < 16; ++i)
    {
        const unsigned send                  = i / 4;
        const unsigned recv                  = i % 4;
        destinations[i].send_buffer_size_set = send != 0;
        destinations[i].recv_buffer_size_set = recv != 0;
        destinations[i].send_buffer_size     = send != 0 ? destination_sizes[send] : state->send_buffer_size;
        destinations[i].recv_buffer_size     = recv != 0 ? destination_sizes[recv] : state->recv_buffer_size;
    }
    state->destinations       = destinations;
    state->destinations_count = 16;

    tcpconnectorTunnelOnStart(t);

    const int expected_send = send_option != 0 ? configured_sizes[send_option] : default_size;
    const int expected_recv = recv_option != 0 ? configured_sizes[recv_option] : default_size;
    require(state->send_buffer_size == expected_send, "incorrect connector send-buffer size");
    require(state->recv_buffer_size == expected_recv, "incorrect connector receive-buffer size");
    for (unsigned i = 0; i < 16; ++i)
    {
        const unsigned send = i / 4;
        const unsigned recv = i % 4;
        require(destinations[i].send_buffer_size == (send != 0 ? destination_sizes[send] : expected_send),
                "incorrect destination send-buffer size");
        require(destinations[i].recv_buffer_size == (recv != 0 ? destination_sizes[recv] : expected_recv),
                "incorrect destination receive-buffer size");
    }
    tunnelDestroy(t);
}

int main(void)
{
    testCaseSet("tcpconnector_mux_buffers_test");
    const int default_sizes[] = {
        0, kDefaultLargeSocketBufferSize, kDefaultLargeSocketBufferSize, kDefaultLargeSocketBufferSize};
    for (unsigned tune = 0; tune < 2; ++tune)
    {
        for (unsigned mux = 0; mux < 4; ++mux)
        {
            for (unsigned send_option = 0; send_option < 4; ++send_option)
            {
                for (unsigned recv_option = 0; recv_option < 4; ++recv_option)
                {
                    testBuffers(tune != 0,
                                (mux & 1U) != 0,
                                (mux & 2U) != 0,
                                send_option,
                                recv_option,
                                tune ? 0 : default_sizes[mux]);
                }
            }
        }
    }
    GSTATE.tcp_tune_enabled = false;
    return 0;
}
