/*
 * Covers: tcplistener mux buffers; the explicit inputs, callbacks and expected results below define this
 * suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: testBuffers
 * Checks: Assertion labels include: incorrect listener send-buffer size; incorrect listener receive-buffer
 * size; incorrect socket-filter update count; socket-filter update targeted the wrong listener
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.tcplistener_mux_buffers_unit
 */
#include "TcpListener/structure.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static unsigned  update_calls;
static tunnel_t *updated_tunnel;
static int       updated_send_size;
static int       updated_recv_size;

void __wrap_socketacceptorUpdateBufferOptions(tunnel_t *tunnel, int send_buffer_size, int recv_buffer_size);


void __wrap_socketacceptorUpdateBufferOptions(tunnel_t *tunnel, int send_buffer_size, int recv_buffer_size)
{
    ++update_calls;
    updated_tunnel    = tunnel;
    updated_send_size = send_buffer_size;
    updated_recv_size = recv_buffer_size;
}

static void testBuffers(bool client, bool server, unsigned send_option, unsigned recv_option, int default_size)
{
    /* Zero is omitted; the remaining values model explicit false, true and an integer. */
    const int      configured_sizes[] = {0, 0, kDefaultLargeSocketBufferSize, 131072};
    node_t         node               = {.type = (char *) "TcpListener"};
    tunnel_chain_t chain              = {.mux_client_tunnel_present = client, .mux_server_tunnel_present = server};
    tunnel_t      *t                  = tunnelCreate(&node, sizeof(tcplistener_tstate_t), 0);
    require(t != NULL, "failed to allocate listener fixture");
    t->chain                    = &chain;
    tcplistener_tstate_t *state = tunnelGetState(t);
    state->send_buffer_size     = configured_sizes[send_option];
    state->recv_buffer_size     = configured_sizes[recv_option];
    state->send_buffer_size_set = send_option != 0;
    state->recv_buffer_size_set = recv_option != 0;
    update_calls                = 0;

    tcplistenerTunnelOnStart(t);

    const int  expected_send   = send_option != 0 ? configured_sizes[send_option] : default_size;
    const int  expected_recv   = recv_option != 0 ? configured_sizes[recv_option] : default_size;
    const bool expected_update = server && (send_option == 0 || recv_option == 0);
    require(state->send_buffer_size == expected_send, "incorrect listener send-buffer size");
    require(state->recv_buffer_size == expected_recv, "incorrect listener receive-buffer size");
    require(update_calls == (unsigned) expected_update, "incorrect socket-filter update count");
    if (expected_update)
    {
        require(updated_tunnel == t, "socket-filter update targeted the wrong listener");
        require(updated_send_size == expected_send && updated_recv_size == expected_recv,
                "socket-filter update used incorrect buffer sizes");
    }
    tunnelDestroy(t);
}

int main(void)
{
    testCaseSet("tcplistener_mux_buffers_test");
    const int default_sizes[] = {0, 0, kDefaultLargeSocketBufferSize, kDefaultLargeSocketBufferSize};
    for (unsigned mux = 0; mux < 4; ++mux)
    {
        for (unsigned send_option = 0; send_option < 4; ++send_option)
        {
            for (unsigned recv_option = 0; recv_option < 4; ++recv_option)
            {
                testBuffers((mux & 1U) != 0, (mux & 2U) != 0, send_option, recv_option, default_sizes[mux]);
            }
        }
    }
    return 0;
}
