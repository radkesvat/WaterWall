#include "structure.h"

#include "loggers/network_logger.h"

// static err_t interfaceInit(struct netif *netif)
// {
//     // IP4_ADDR(&netif->ip_addr.u_addr.ip4, 192, 168, 2, 10);  // Set IP address
//     // IP4_ADDR(&netif->gw.u_addr.ip4, 192, 168, 2, 1);        // Set gateway
//     // IP4_ADDR(&netif->netmask.u_addr.ip4, 255, 255, 255, 0); // Set subnet mask

//     netif->output = ptcNetifOutput;
//     /* later our lwip ip hooks identify this netif form this flag */
//     netif->flags |= NETIF_FLAG_L3TO4;

//     return ERR_OK;
// }

tunnel_t *ptcTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(ptc_tstate_t), sizeof(ptc_lstate_t));

    t->fnInitU    = &ptcTunnelUpStreamInit;
    t->fnPayloadU = &ptcTunnelUpStreamPayload;
    t->fnPayloadD = &ptcTunnelDownStreamPayload;
    t->fnFinD     = &ptcTunnelDownStreamFinish;
    t->fnInitD    = &ptcTunnelDownStreamInit;
    t->fnEstD     = &ptcTunnelDownStreamEst;
    t->fnPauseD   = &ptcTunnelDownStreamPause;
    t->fnResumeD  = &ptcTunnelDownStreamResume;

    t->onPrepair = &ptcTunnelOnPrepair;
    t->onStart   = &ptcTunnelOnStart;
    t->onDestroy = &ptcTunnelDestroy;

    // ptc_tstate_t *state = tunnelGetState(t);

    // const cJSON *settings = node->node_settings_json;

    // if (! checkJsonIsObjectAndHasChild(settings))
    // {
    //     LOGF("JSON Error: PacketToConnection->settings (object field) : The object was empty or invalid");
    //     return NULL;
    // }

    initTcpIpStack();

    LWIP_MEMPOOL_INIT(RX_POOL);

    // GSTATE.lwip_process_v4_hook = ptcHookV4;

    // char *address = NULL;
    // if (! getStringFromJsonObject(&address, settings, "address"))
    // {
    //     LOGF("JSON Error: PacketToConnection->settings->address (string field) : The data was empty or invalid");

    //     return NULL;
    // }

    // char *gateway = NULL;
    // if (! getStringFromJsonObject(&gateway, settings, "gateway"))
    // {
    //     LOGF("JSON Error: PacketToConnection->settings->gateway (string field) : The data was empty or invalid");

    //     return NULL;
    // }

    // ip_addr_t addr;
    // ip_addr_t addr_mask;
    // if (4 != parseIPWithSubnetMask(address, &addr, &addr_mask))
    // {
    //     LOGF("JSON Error: PacketToConnection->settings->address parsing error");
    //     return NULL;
    // }
    // ip_addr_t gw;

    // if (4 != pareIpAddress(gateway, &gw))
    // {
    //     LOGF("JSON Error: PacketToConnection->settings->gateway parsing error");
    //     return NULL;
    // }

    // struct netif *netif = &state->netif;

    // state->udp_free = natpcbsInitMem(state->udp_storage, LWIP_NAT_UDP_PCB_SZ, LWIP_NAT_UDP_MAX);
    // state->tcp_free = natpcbsInitMem(state->tcp_storage, LWIP_NAT_TCP_PCB_SZ, LWIP_NAT_TCP_MAX);

    // // Add and configure the network interface
    // // netif_add(netif, IP4_ADDR_ANY4, IP4_ADDR_ANY4, IP4_ADDR_ANY4, NULL, interface_init, ip_input);
    // netif_add(netif, &addr.u_addr.ip4, &addr_mask.u_addr.ip4, &gw.u_addr.ip4, t, interfaceInit, tcpip_input);

    // // netif_set_default(netif);
    // netif_set_up(netif);

    // LOGD("node %s: LWIP NETIF IP:   %s", node->name, ip4addr_ntoa(netif_ip4_addr(netif)));
    // LOGD("node %s: LWIP NETIF MASK: %s", node->name, ip4addr_ntoa(netif_ip4_netmask(netif)));
    // LOGD("node %s: LWIP NETIF GW:   %s", node->name, ip4addr_ntoa(netif_ip4_gw(netif)));

    return t;
}
