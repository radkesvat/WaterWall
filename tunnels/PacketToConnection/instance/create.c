#include "structure.h"

#include "loggers/network_logger.h"

static err_t interface_init(struct netif *netif) {
    IP4_ADDR(&netif->ip_addr.u_addr.ip4, 192, 168, 2, 10); // Set IP address
    IP4_ADDR(&netif->gw.u_addr.ip4, 192, 168, 2, 1);      // Set gateway
    IP4_ADDR(&netif->netmask.u_addr.ip4, 255, 255, 255, 0); // Set subnet mask
    return ERR_OK;
}

tunnel_t *ptcTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(ptc_tstate_t), sizeof(ptc_lstate_t));

    t->fnPayloadU = &ptcTunnelUpStreamPayload;

    t->fnPayloadD = &ptcTunnelDownStreamPayload;

    t->onPrepair = &ptcTunnelOnPrepair;
    t->onStart   = &ptcTunnelOnStart;
    t->onDestroy = &ptcTunnelDestroy;

    ptc_tstate_t *state = tunnelGetState(t);

    const cJSON *settings = node->node_settings_json;

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: PacketToConnection->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    if (GSTATE.flag_lwip_initialized == 0)
    {
        // Initialize the lwIP stack
        tcpipInit(NULL, NULL);
        GSTATE.flag_lwip_initialized = 1;
    }

    struct netif *netif = &state->netif;
    // Add and configure the network interface
    // netif_add(netif, IP4_ADDR_ANY4, IP4_ADDR_ANY4, IP4_ADDR_ANY4, NULL, interface_init, ip_input);
    netif_add(netif, IP4_ADDR_ANY4, IP4_ADDR_ANY4, IP4_ADDR_ANY4, NULL, interface_init, tcpip_input);
    netif_set_default(netif);
    netif_set_up(netif);
    return t;
}
