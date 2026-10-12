/*
 * Covers: connectiontopackets netif contract; the explicit inputs, callbacks and expected results below
 * define this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: settings/prepare destination selection; production MTU; fragment output refusal
 * Checks: Assertion labels include: production settings loading failed; production netif creation failed;
 * production netif did not apply the effective MTU; second instance changed first MTU
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.connectiontopackets_netif_contract_unit
 */
#include "wwapi.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

#include "ConnectionToPackets/structure.h"
#include "fixtures/lwip/lwip_test_runtime.h"

#include "lwip/init.h"
#include "lwip/ip4_frag.h"
#include "lwip/udp.h"

static uint32_t g_output_count;
static int32_t  g_fail_output_at = -1;


static err_t captureOutput(struct netif *netif, struct pbuf *p, const ip4_addr_t *destination)
{
    discard netif;
    discard p;
    discard destination;

    if (g_fail_output_at >= 0 && g_output_count == (uint32_t) g_fail_output_at)
    {
        return ERR_MEM;
    }

    ++g_output_count;
    return ERR_OK;
}

static err_t captureNetifInit(struct netif *netif)
{
    netif->name[0] = 'c';
    netif->name[1] = 't';
    netif->output  = captureOutput;
    netif->mtu     = 1500;
    netif->flags   = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
    return ERR_OK;
}

static void testProductionSettingsReachProductionNetif(void)
{
    static const char *settings_json[] = {
        "{\"source-ipv4\":\"10.90.0.1\"}",
        "{\"source-ipv4\":\"10.90.0.1\",\"mtu\":1280}",
    };
    static const uint32_t expected_mtu[] = {1420, 1280};

    const uint16_t saved_default = CORE_DEFAULT_MTU;
    tunnel_t      *instances[2];
    CORE_DEFAULT_MTU = 1420;

    for (uint32_t i = 0; i < ARRAY_SIZE(expected_mtu); ++i)
    {
        tunnel_t *t = tunnelCreate(NULL, sizeof(ctp_tstate_t), sizeof(ctp_lstate_t));
        require(t != NULL, "failed to create the tunnel fixture");

        ctp_tstate_t *ts = tunnelGetState(t);
        memoryZero(ts, sizeof(*ts));
        atomic_init(&ts->stopping, false);

        cJSON *settings = cJSON_Parse(settings_json[i]);
        require(settings != NULL, "failed to parse settings");
        require(ctpLoadSettings(ts, settings), "production settings loading failed");

        ts->netifs_count = 1;
        ts->netifs       = memoryAllocateZero(sizeof(*ts->netifs));
        require(ts->netifs != NULL, "failed to allocate the netif table");

        CORE_DEFAULT_MTU     = 68;
        ctp_netif_ctx_t *ctx = ctpEnsureNetifLocked(t, 0);
        require(ctx != NULL, "production netif creation failed");
        require(ctx->netif.mtu == expected_mtu[i], "production netif did not apply the effective MTU");

        discard ip4_reass_purge_netif(&ctx->netif);
        netif_remove(&ctx->netif);
        memoryFree(ctx);
        memoryFree(ts->netifs);
        cJSON_Delete(settings);
        instances[i]     = t;
        CORE_DEFAULT_MTU = 1420;
    }
    require(((ctp_tstate_t *) tunnelGetState(instances[0]))->mtu == 1420, "second instance changed first MTU");
    tunnelDestroy(instances[1]);
    tunnelDestroy(instances[0]);
    CORE_DEFAULT_MTU = saved_default;
}

static void testConfiguredDestinationPreparation(void)
{
    static const struct
    {
        const char *name, *settings, *incoming_address, *expected_address;
        uint16_t    incoming_port, expected_port;
        uint8_t     source_protocol, destination_protocol, expected_protocol;
        bool        accepted;
    } cases[] = {
        {"omitted selectors", "{}", "10.90.0.2", "10.90.0.2", 443, 443, IP_PROTO_UDP, IP_PROTO_TCP, IP_PROTO_TCP, true},
        {"explicit context selectors",
         "{\"target-address\":\"dest_context->address\",\"port\":\"dest_context->port\"}",
         "incoming.test",
         "incoming.test",
         53,
         53,
         IP_PROTO_TCP,
         IP_PROTO_UDP,
         IP_PROTO_UDP,
         true},
        {"static destination without incoming context",
         "{\"target-address\":\"10.90.0.3\",\"port\":443}",
         NULL,
         "10.90.0.3",
         0,
         443,
         IP_PROTO_TCP,
         0,
         IP_PROTO_TCP,
         true},
        {"static address preserves incoming port and protocol",
         "{\"target-address\":\"10.90.0.3\"}",
         "incoming.test",
         "10.90.0.3",
         53,
         53,
         IP_PROTO_TCP,
         IP_PROTO_UDP,
         IP_PROTO_UDP,
         true},
        {"static port preserves incoming address",
         "{\"port\":65535}",
         "incoming.test",
         "incoming.test",
         80,
         65535,
         IP_PROTO_UDP,
         IP_PROTO_TCP,
         IP_PROTO_TCP,
         true},
        {"configured domain replaces incoming destination",
         "{\"target-address\":\"configured.test\",\"port\":1}",
         "10.90.0.2",
         "configured.test",
         80,
         1,
         IP_PROTO_TCP,
         IP_PROTO_UDP,
         IP_PROTO_UDP,
         true},
        {"missing incoming port", "{\"target-address\":\"10.90.0.3\"}", NULL, NULL, 0, 0, IP_PROTO_TCP, 0, 0, false},
        {"missing incoming address", "{\"port\":443}", NULL, NULL, 0, 0, IP_PROTO_TCP, 0, 0, false},
        {"missing protocol", "{\"target-address\":\"10.90.0.3\",\"port\":443}", NULL, NULL, 0, 0, 0, 0, 0, false},
        {"unsupported destination protocol remains authoritative",
         "{\"target-address\":\"10.90.0.3\",\"port\":443}",
         "10.90.0.2",
         NULL,
         80,
         0,
         IP_PROTO_TCP,
         IP_PROTO_ICMP,
         0,
         false},
    };
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        testCaseSet(cases[i].name);
        tunnel_t *t = tunnelCreate(NULL, sizeof(ctp_tstate_t), 0);
        require(t != NULL, "failed to create destination fixture");
        ctp_tstate_t *ts       = tunnelGetState(t);
        cJSON        *settings = cJSON_Parse(cases[i].settings);
        require(settings != NULL, "failed to parse destination settings");
        cJSON_AddStringToObject(settings, "source-ipv4", "10.90.0.1");
        cJSON_AddNumberToObject(settings, "mtu", 1500);
        require(ctpLoadSettings(ts, settings), "valid destination settings rejected");
        cJSON_Delete(settings);

        line_t             line = {0};
        address_context_t *dest = lineGetDestinationAddressContext(&line);
        if (cases[i].incoming_address != NULL && ! addresscontextSetIpAddress(dest, cases[i].incoming_address))
        {
            addresscontextDomainSetByString(dest, cases[i].incoming_address);
        }
        addresscontextSetPort(dest, cases[i].incoming_port);
        addresscontextSetOnlyProtocol(dest, cases[i].destination_protocol);
        addresscontextSetOnlyProtocol(lineGetSourceAddressContext(&line), cases[i].source_protocol);
        ctp_domain_resolver_lstate_t resolver_state = {0};
        require(ctpDomainResolverPrepare(NULL, t, &line, &resolver_state) == cases[i].accepted,
                "prepare acceptance differed");
        if (cases[i].accepted)
        {
            ip_addr_t expected_ip;
            if (ipaddr_aton(cases[i].expected_address, &expected_ip))
            {
                require(addresscontextIsIp(dest) && ip_addr_cmp(&dest->ip_address, &expected_ip),
                        "prepared IP differed");
            }
            else
            {
                require(addresscontextIsDomain(dest) && strcmp(dest->domain, cases[i].expected_address) == 0 &&
                            ! dest->domain_resolved,
                        "prepared domain differed or skipped DNS");
            }
            require(dest->port == cases[i].expected_port, "prepared port differed");
            require(resolver_state.protocol == cases[i].expected_protocol &&
                        dest->proto_tcp == (cases[i].expected_protocol == IP_PROTO_TCP) &&
                        dest->proto_udp == (cases[i].expected_protocol == IP_PROTO_UDP) && ! dest->proto_icmp &&
                        ! dest->proto_packet,
                    "address replacement changed protocol selection");
            require(dest->domain_strategy == kDsOnlyIpV4, "prepare did not select IPv4-only resolution");
            if (strcmp(cases[i].expected_address, "configured.test") == 0)
            {
                line_t                       other_line           = {0};
                ctp_domain_resolver_lstate_t other_resolver_state = {0};
                address_context_t           *other_dest           = lineGetDestinationAddressContext(&other_line);
                addresscontextSetOnlyProtocol(lineGetSourceAddressContext(&other_line), IP_PROTO_TCP);
                require(ctpDomainResolverPrepare(NULL, t, &other_line, &other_resolver_state),
                        "configured domain could not prepare a second line");
                addresscontextReset(dest);
                require(addresscontextIsDomain(other_dest) && strcmp(other_dest->domain, "configured.test") == 0 &&
                            other_dest->port == 1 && other_resolver_state.protocol == IP_PROTO_TCP,
                        "one line changed another line's configured endpoint or protocol");
                addresscontextReset(other_dest);
            }
        }
        addresscontextReset(dest);
        addresscontextReset(&ts->target_addr);
        tunnelDestroy(t);
    }
}

static void testInvalidDestinationSettings(void)
{
    static const char *invalid[] = {
        "{\"target-address\":null}",
        "{\"target-address\":42}",
        "{\"target-address\":\"\"}",
        "{\"target-address\":\"::1\"}",
        "{\"port\":null}",
        "{\"port\":true}",
        "{\"port\":0}",
        "{\"port\":65536}",
        "{\"port\":1.5}",
        "{\"port\":\"443\"}",
    };
    testCaseSet("invalid destination settings");
    for (size_t i = 0; i <= ARRAY_SIZE(invalid); ++i)
    {
        cJSON *settings = i < ARRAY_SIZE(invalid) ? cJSON_Parse(invalid[i]) : cJSON_CreateObject();
        require(settings != NULL, "failed to create invalid settings fixture");
        if (i == ARRAY_SIZE(invalid))
        {
            char oversized[UINT8_MAX + 2];
            memset(oversized, 'a', sizeof(oversized) - 1);
            oversized[sizeof(oversized) - 1] = '\0';
            cJSON_AddStringToObject(settings, "target-address", oversized);
        }
        cJSON_AddStringToObject(settings, "source-ipv4", "10.90.0.1");
        cJSON_AddNumberToObject(settings, "mtu", 1500);
        ctp_tstate_t state = {0};
        require(! ctpLoadSettings(&state, settings), "invalid destination setting was accepted");
        addresscontextReset(&state.target_addr);
        cJSON_Delete(settings);
    }
}

static void testFragmentOutputFailureStopsAndPropagates(void)
{
    struct netif netif;
    ip4_addr_t   local;
    ip4_addr_t   netmask;
    ip4_addr_t   gateway;
    ip4_addr_t   remote;

    IP4_ADDR(&local, 10, 90, 0, 1);
    IP4_ADDR(&netmask, 255, 255, 255, 0);
    IP4_ADDR(&gateway, 0, 0, 0, 0);
    IP4_ADDR(&remote, 10, 90, 0, 2);

    memoryZero(&netif, sizeof(netif));
    require(netif_add(&netif, &local, &netmask, &gateway, NULL, captureNetifInit, ip_input) != NULL,
            "failed to add the capture netif");
    netif_set_up(&netif);

    struct udp_pcb *pcb = udp_new_ip_type(IPADDR_TYPE_V4);
    require(pcb != NULL, "failed to create a UDP pcb");
    require(udp_bind(pcb, IP4_ADDR_ANY, 40000) == ERR_OK, "failed to bind the UDP pcb");

    uint8_t payload[8192];
    for (uint32_t i = 0; i < ARRAY_SIZE(payload); ++i)
    {
        payload[i] = (uint8_t) (i * 31U + 7U);
    }

    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, sizeof(payload), PBUF_RAM);
    require(p != NULL && pbuf_take(p, payload, sizeof(payload)) == ERR_OK, "failed to create the UDP payload");

    ip_addr_t remote_ip;
    ipAddrCopyFromIp4(remote_ip, remote);
    g_output_count   = 0;
    g_fail_output_at = 2;

    const err_t result = udp_sendto_if(pcb, p, &remote_ip, 40001, &netif);

    g_fail_output_at = -1;
    pbuf_free(p);
    require(result != ERR_OK, "a refused fragment was reported as sent");
    require(g_output_count == 2, "lwIP emitted fragments after the first output refusal");

    udp_remove(pcb);
    netif_remove(&netif);
}

int main(void)
{
    testCaseSet("connectiontopackets_netif_contract_test");
    require(lwipTestRuntimeInitialize(), "failed to initialize the lwIP random runtime");
    lwipTestEngineBegin(1);
    testConfiguredDestinationPreparation();
    testInvalidDestinationSettings();
    testCaseSet("production netif contract");
    testProductionSettingsReachProductionNetif();
    testFragmentOutputFailureStopsAndPropagates();
    wwLwipTestEraseTcpIsnSecret();
    lwipTestEngineEnd();
    lwipTestRuntimeCleanup();
    puts("ConnectionToPackets netif contract tests passed");
    return 0;
}
