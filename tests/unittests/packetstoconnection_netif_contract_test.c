#include "PacketsToConnection/structure.h"
#include "lwip/init.h"
#include "lwip/udp.h"
#include "lwip_test_runtime.h"
#include "worker_registry_fixture.h"

static unsigned packet_count;
static unsigned packet_limit;
static void     require(bool ok, const char *message)
{
    if (! ok)
    {
        fprintf(stderr, "PacketsToConnection MTU: %s\n", message);
        exit(1);
    }
}

static err_t captureOutput(struct netif *netif, struct pbuf *p, const ip4_addr_t *destination)
{
    discard destination;
    require(netif->mtu == packet_limit, "wrong interface used for response");
    require(p->tot_len <= packet_limit, "fragment exceeds instance MTU");
    ++packet_count;
    return ERR_OK;
}

static tunnel_t *create(const char *json)
{
    cJSON        *settings = json ? cJSON_Parse(json) : NULL;
    static node_t node;
    node.node_settings_json = settings;
    tunnel_t *t             = ptcTunnelCreate(&node);
    cJSON_Delete(settings);
    return t;
}

static void destroy(tunnel_t *t)
{
    ptc_tstate_t *ts = tunnelGetState(t);
    ptcDestroyRouteContexts(t);
    mutexDestroy(&ts->owned_lines_lock);
    tunnelDestroy(t);
}

static void checkResponse(struct netif *netif)
{
    packet_count        = 0;
    packet_limit        = netif->mtu;
    netif->output       = captureOutput;
    struct udp_pcb *pcb = udp_new_ip_type(IPADDR_TYPE_V4);
    require(pcb != NULL, "UDP allocation failed");
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, 4096, PBUF_RAM);
    require(p != NULL, "response allocation failed");
    memset(p->payload, 0, p->len);
    ip_addr_t remote;
    IP_ADDR4(&remote, 10, 90, 0, 2);
    require(udp_sendto_if(pcb, p, &remote, 40001, netif) == ERR_OK, "response send failed");
    require(packet_count > 1, "response was not fragmented");
    pbuf_free(p);
    udp_remove(pcb);
}

int main(void)
{
    require(lwipTestRuntimeInitialize(), "random runtime initialization failed");
    lwip_init();
    test_worker_registry_t registry = {0};
    GSTATE.workers_count            = 3;
    testWorkerRegistryInstall(&registry);
    GSTATE.flag_lwip_initialized = 1;
    const uint16_t saved         = CORE_DEFAULT_MTU;
    CORE_DEFAULT_MTU             = 1420;
    tunnel_t *first              = create(NULL);
    tunnel_t *second             = create("{\"mtu\":1000}");
    require(first && second, "valid construction failed");
    CORE_DEFAULT_MTU = 0;
    require(create(NULL) == NULL && create("{}") == NULL, "invalid inherited MTU accepted");
    static const char *values[] = {"68",
                                   "65535",
                                   "1500",
                                   "67",
                                   "65536",
                                   "70000",
                                   "0",
                                   "-1",
                                   "null",
                                   "true",
                                   "false",
                                   "[]",
                                   "{}",
                                   "\"1500\"",
                                   "1500.5",
                                   "9223372036854775807"};
    for (unsigned i = 0; i < ARRAY_SIZE(values); ++i)
    {
        char json[128];
        snprintf(json, sizeof(json), "{\"mtu\":%s}", values[i]);
        tunnel_t *t = create(json);
        require((t != NULL) == (i < 3), "MTU parsing boundary/type mismatch");
        if (t)
            destroy(t);
    }
    tunnel_t      *instances[] = {first, second};
    const unsigned expected[]  = {1420, 1000};
    for (unsigned i = 0; i < 2; ++i)
    {
        ptc_tstate_t *ts       = tunnelGetState(instances[i]);
        ts->route_worker_count = 2;
        ts->routes_v4          = memoryAllocateZero(2 * sizeof(*ts->routes_v4));
        require(ts->routes_v4 != NULL, "route slots allocation failed");
        for (wid_t wid = 0; wid < 2; ++wid)
        {
            testWorkerBindWID(wid);
            interface_route_context_t *route = ptcFindOrCreateRouteContextV4(instances[i], wid, NULL);
            require(route != NULL && route->netif.mtu == expected[i], "lazy netif did not use its instance snapshot");
            checkResponse(&route->netif);
        }
    }
    destroy(second);
    destroy(first);
    CORE_DEFAULT_MTU             = saved;
    GSTATE.flag_lwip_initialized = 0;
    testWorkerRegistryRestore(&registry);
    GSTATE.workers_count = 0;
    wwLwipTestEraseTcpIsnSecret();
    lwipTestRuntimeCleanup();
    return 0;
}
