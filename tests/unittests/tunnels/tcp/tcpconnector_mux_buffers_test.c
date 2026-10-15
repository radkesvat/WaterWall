/*
 * Covers: tcpconnector mux buffers; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: testBuffers, testAddressSettings, testFreeBindBoundaries
 * Checks: Assertion labels include: incorrect connector send-buffer size; incorrect connector
 * receive-buffer size; incorrect destination send-buffer size; incorrect destination receive-buffer size
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.tcpconnector_mux_buffers_unit
 */
#include "TcpConnector/structure.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

#ifdef TCP_CONNECTOR_TEST_RANDOM_WRAP
static uint32_t random32_value;
static uint64_t random64_value;

uint32_t __wrap_fastRand32(void);
uint64_t __wrap_fastRand64(void);

uint32_t __wrap_fastRand32(void)
{
    return random32_value;
}

uint64_t __wrap_fastRand64(void)
{
    return random64_value;
}
#endif

static void testAddressSetting(const char *address, bool accepted, uint64_t expected_range, size_t domain_length)
{
    for (unsigned weighted = 0; weighted < 2; ++weighted)
    {
        cJSON *settings    = cJSON_CreateObject();
        cJSON *destination = settings;
        if (weighted)
        {
            cJSON *destinations = cJSON_AddArrayToObject(settings, "addresses");
            destination         = cJSON_CreateObject();
            require(cJSON_AddItemToArray(destinations, destination), "add destination fixture");
            cJSON_AddNumberToObject(destination, "weight", 1);
        }
        cJSON_AddStringToObject(destination, "address", address);
        cJSON_AddNumberToObject(destination, "port", 443);
        node_t node = {
            .name = (char *) "tcp-constructor-test", .type = (char *) "TcpConnector", .node_settings_json = settings};
        ww_startup_context_t startup = {0};
        wwStartupContextBegin(&startup);
        tunnel_t           *t           = tcpconnectorTunnelCreate(&node);
        ww_startup_result_t result      = wwStartupContextEnd(&startup);
        const bool          constructed = t != NULL;
        if (constructed)
        {
            tcpconnector_tstate_t *state = tunnelGetState(t);
            const uint64_t range = weighted ? state->destinations[0].outbound_ip_range : state->outbound_ip_range;
            const address_context_t *context =
                weighted ? &state->destinations[0].constant_dest_addr : &state->constant_dest_addr;
            if (accepted)
            {
                require(wwStartupSucceeded(result), "valid destination recorded a startup failure");
                require(range == expected_range, "CIDR produced an incorrect randomization range");
                if (domain_length != 0)
                    require(addresscontextIsDomain(context) && context->domain_len == domain_length &&
                                memcmp(context->domain, address, domain_length) == 0,
                            "domain length was narrowed or domain bytes changed");
            }
            tcpconnectorTunnelDestroy(t, wwLifecycleStartupRollback());
        }
        cJSON_Delete(settings);
        require(constructed == accepted, "constructor accepted malformed destination or rejected a valid boundary");
    }
}

static void testAddressSettings(void)
{
    const char *invalid[] = {"",
                             "192.0.2.1/not-a-prefix",
                             "192.0.2.1/24tail",
                             "192.0.2.1/",
                             "192.0.2.1/-1",
                             "192.0.2.1/33",
                             "2001:db8::1/63",
                             "2001:db8::1/129",
                             "2001:db8::1/999999999999999999999"};
    for (size_t i = 0; i < ARRAY_SIZE(invalid); ++i)
    {
        testCaseSet(invalid[i][0] == '\0' ? "TcpConnector empty address" : invalid[i]);
        testAddressSetting(invalid[i], false, 0, 0);
    }
    const struct
    {
        const char *address;
        uint64_t    range;
    } valid[] = {{"192.0.2.1/0", UINT64_C(1) << 32},
                 {"192.0.2.1/24", UINT64_C(1) << 8},
                 {"192.0.2.1/32", 0},
                 {"2001:db8::1/64", UINT64_MAX},
                 {"2001:db8::1/65", UINT64_C(1) << 63},
                 {"2001:db8::1/128", 1}};
    for (size_t i = 0; i < ARRAY_SIZE(valid); ++i)
    {
        testCaseSet(valid[i].address);
        testAddressSetting(valid[i].address, true, valid[i].range, 0);
    }
    char domain[258];
    memset(domain, 'a', sizeof(domain));
    for (size_t length = 255; length <= 257; ++length)
    {
        testCaseSet("TcpConnector domain length boundary");
        domain[length] = '\0';
        testAddressSetting(domain, length == 255, 0, length);
        domain[length] = 'a';
    }
}

#ifdef TCP_CONNECTOR_TEST_RANDOM_WRAP
static void testFreeBindBoundaries(void)
{
    testCaseSet("TcpConnector IPv4 full host range");
    address_context_t context = {0};
    require(addresscontextSetIpAddress(&context, "192.0.2.1"), "set IPv4 fixture");
    random32_value = UINT32_MAX;
    require(tcpconnectorApplyFreeBindRandomDestIp(&context, UINT64_C(1) << 32), "apply IPv4 /0 range");
    require(ntohl(context.ip_address.u_addr.ip4.addr) == UINT32_MAX, "IPv4 /0 did not include the highest host");

    testCaseSet("TcpConnector IPv6 full host range");
    const uint64_t values[] = {0, UINT64_MAX};
    for (size_t i = 0; i < ARRAY_SIZE(values); ++i)
    {
        require(addresscontextSetIpAddress(&context, "2001:db8::1"), "set IPv6 fixture");
        uint8_t prefix[8];
        memoryCopy(prefix, &context.ip_address.u_addr.ip6, sizeof(prefix));
        random64_value = values[i];
        require(tcpconnectorApplyFreeBindRandomDestIp(&context, UINT64_MAX), "apply IPv6 /64 range");
        uint64_t host;
        memoryCopy(&host, (const uint8_t *) &context.ip_address.u_addr.ip6 + 8, sizeof(host));
        require(ntohll(host) == values[i], "IPv6 /64 retained a base host bit or excluded the highest host");
        require(memcmp(prefix, &context.ip_address.u_addr.ip6, sizeof(prefix)) == 0, "IPv6 /64 changed its prefix");
    }

    testCaseSet("TcpConnector IPv6 single host");
    require(addresscontextSetIpAddress(&context, "2001:db8::1"), "set IPv6 /128 fixture");
    ip_addr_t original = context.ip_address;
    require(tcpconnectorApplyFreeBindRandomDestIp(&context, 1), "apply IPv6 /128 range");
    require(memcmp(&original, &context.ip_address, sizeof(original)) == 0, "IPv6 /128 changed its only host");
}
#endif

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
                    testBuffers(
                        tune != 0, (mux & 1U) != 0, (mux & 2U) != 0, send_option, recv_option, default_sizes[mux]);
                }
            }
        }
    }
    GSTATE.tcp_tune_enabled = false;
    GSTATE.workers_count    = 1;
    GSTATE.domain_strategy  = kDsPreferIpV4;
    testAddressSettings();
#ifdef TCP_CONNECTOR_TEST_RANDOM_WRAP
    testFreeBindBoundaries();
#endif
    return 0;
}
