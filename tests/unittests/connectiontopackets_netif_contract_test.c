#include "wwapi.h"

#include "ConnectionToPackets/structure.h"

#include "lwip/init.h"
#include "lwip/ip4_frag.h"
#include "lwip/udp.h"

static uint32_t g_output_count;
static int32_t  g_fail_output_at = -1;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "connectiontopackets_netif_contract_test: %s\n", message);
        exit(1);
    }
}

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

    GLOBAL_MTU_SIZE = 1420;

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

        ctp_netif_ctx_t *ctx = ctpEnsureNetifLocked(t, 0);
        require(ctx != NULL, "production netif creation failed");
        require(ctx->netif.mtu == expected_mtu[i], "production netif did not apply the effective MTU");

        discard ip4_reass_purge_netif(&ctx->netif);
        netif_remove(&ctx->netif);
        memoryFree(ctx);
        memoryFree(ts->netifs);
        cJSON_Delete(settings);
        tunnelDestroy(t);
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
    lwip_init();
    testProductionSettingsReachProductionNetif();
    testFragmentOutputFailureStopsAndPropagates();
    puts("ConnectionToPackets netif contract tests passed");
    return 0;
}
