#include "structure.h"

#include "loggers/network_logger.h"

err_t wireguardifPeerOutput(wgd_tstate_t *ts, sbuf_t *q, wireguard_peer_t *peer)
{
    wireguard_device_t *device = (wireguard_device_t *) ts->state;
    // Send to last know port, not the connect port
    // TODO: Support DSCP and ECN - lwip requires this set on PCB globally, not per packet
    return udpSendTo(device->udp_pcb, q, &peer->ip, peer->port);
}

err_t wireguardifDeviceOutput(wireguard_device_t *device, sbuf_t *q, const ip_address_t *ipaddr, uint16_t port)
{
    return udpSendTo(device->udp_pcb, q, ipaddr, port);
}

err_t wireguardifAddPeer(wgd_tstate_t *ts, wireguardif_peer_t *p, uint8_t *peer_index)
{
    LWIP_ASSERT("ts != NULL", (ts != NULL));
    LWIP_ASSERT("state != NULL", (ts->state != NULL));
    LWIP_ASSERT("p != NULL", (p != NULL));
    wireguard_device_t *device = (wireguard_device_t *) ts->state;
    err_t               result;
    uint8_t             public_key[WIREGUARD_PUBLIC_KEY_LEN];
    size_t              public_key_len = sizeof(public_key);
    wireguard_peer_t   *peer           = NULL;

    uint32_t t1 = getTickMS();

    if (wireguard_base64_decode(p->public_key, public_key, &public_key_len) &&
        (public_key_len == WIREGUARD_PUBLIC_KEY_LEN))
    {

        // See if the peer is already registered
        peer = peerLookupByPubkey(device, public_key);
        if (! peer)
        {
            // Not active - see if we have room to allocate a new one
            peer = peerAlloc(device);
            if (peer)
            {

                if (wireguardPeerInit(device, peer, public_key, p->preshared_key))
                {

                    peer->connect_ip   = p->endpoint_ip;
                    peer->connect_port = p->endport_port;
                    peer->ip           = peer->connect_ip;
                    peer->port         = peer->connect_port;
                    if (p->keep_alive == WIREGUARDIF_KEEPALIVE_DEFAULT)
                    {
                        peer->keepalive_interval = KEEPALIVE_TIMEOUT;
                    }
                    else
                    {
                        peer->keepalive_interval = p->keep_alive;
                    }
                    peerAddIp(peer, p->allowed_ip, p->allowed_mask);
                    memcpy(peer->greatest_timestamp, p->greatest_timestamp, sizeof(peer->greatest_timestamp));

                    result = ERR_OK;
                }
                else
                {
                    result = ERR_ARG;
                }
            }
            else
            {
                result = ERR_MEM;
            }
        }
        else
        {
            result = ERR_OK;
        }
    }
    else
    {
        result = ERR_ARG;
    }

    uint32_t t2 = getTickMS();
    printf("Adding peer took %ldms\r\n", (t2 - t1));

    if (peer_index)
    {
        if (peer)
        {
            *peer_index = wireguard_peer_index(device, peer);
        }
        else
        {
            *peer_index = WIREGUARDIF_INVALID_INDEX;
        }
    }
    return result;
}

err_t wireguardifInit(wgd_tstate_t *ts)
{
    err_t                    result;
    wireguardif_init_data_t *init_data;
    wireguard_device_t      *device;
    udp_pcb_t               *udp;
    uint8_t                  private_key[WIREGUARD_PRIVATE_KEY_LEN];
    size_t                   private_key_len = sizeof(private_key);

    assert(ts != NULL);

    // We need to initialise the wireguard module
    wireguardInit();

    if (ts)
    {

        // The init data is passed into the netif_add call as the 'state' - we will replace this with our private state
        // data
        init_data = &ts->device_configuration;

    
        if (wwBase64Decode(init_data->private_key,strlen(initdata_private_key),&private_key) &&
            (private_key_len == WIREGUARD_PRIVATE_KEY_LEN))
        {

            udp = udpNew();

            if (udp)
            {
                result = udpBind(
                    udp, IP_ADDR_ANY,
                    init_data->listen_port); // Note this listens on all interfaces! Really just want the passed ts
                if (result == ERR_OK)
                {
                    device = (wireguard_device_t *) memCalloc(1, sizeof(wireguard_device_t));
                    if (device)
                    {
                        device->ts = ts;
                        if (init_data->bind_netif)
                        {
                            udpBindNetif(udp, init_data->bind_netif);
                        }
                        device->udp_pcb = udp;
                        // Per-wireguard ts/device setup
                        uint32_t t1 = getTickMS();
                        if (wireguard_device_init(device, private_key))
                        {
                            uint32_t t2 = getTickMS();
                            printf("Device init took %ldms\r\n", (t2 - t1));

#if LWIP_CHECKSUM_CTRL_PER_NETIF
                            netifSetChecksumCtrl(ts, NETIF_CHECKSUM_ENABLE_ALL);
#endif
                            ts->state      = device;
                            ts->name[0]    = 'w';
                            ts->name[1]    = 'g';
                            ts->output     = wireguardifOutput;
                            ts->linkoutput = NULL;
                            ts->hwaddr_len = 0;
                            ts->mtu        = WIREGUARDIF_MTU;
                            // We set up no state flags here - caller should set them
                            // NETIF_FLAG_LINK_UP is automatically set/cleared when at least one peer is connected
                            ts->flags = 0;

                            udpRecv(udp, wireguardifNetworkRx, device);

                            // Start a periodic timer for this wireguard device
                            sysTimeout(WIREGUARDIF_TIMER_MSECS, wireguardifTmr, device);

                            result = ERR_OK;
                        }
                        else
                        {
                            memFree(device);
                            device = NULL;
                            udpRemove(udp);
                            result = ERR_ARG;
                        }
                    }
                    else
                    {
                        udpRemove(udp);
                        result = ERR_MEM;
                    }
                }
                else
                {
                    udpRemove(udp);
                }
            }
            else
            {
                result = ERR_MEM;
            }
        }
        else
        {
            result = ERR_ARG;
        }
    }
    else
    {
        result = ERR_ARG;
    }
    return result;
}
