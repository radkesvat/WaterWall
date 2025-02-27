#include "structure.h"

#include "loggers/network_logger.h"

static void passToTcpIp(sbuf_t *buf, wid_t wid, struct netif *inp)
{

    struct pbuf *p = pbufAlloc(PBUF_RAW, sbufGetLength(buf), PBUF_REF);

    p->payload = &buf->buf[0];
    // LOCK_TCPIP_CORE();
    inp->input(p, inp);
    // UNLOCK_TCPIP_CORE();

    // since PBUF_REF is used, lwip wont delay this buffer after call stack, if it needs queue then it will be
    // duplicated so we can free it now
    bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
}

static err_t interfaceInit(struct netif *netif)
{

    /* later our lwip ip hooks identify this netif form this flag */
    netif->flags |= NETIF_FLAG_L3TO4;
    netif->output = ptcNetifOutput;

    return ERR_OK;
}

static void processV4(tunnel_t *t, line_t *l, sbuf_t *buf)
{

    ptc_tstate_t  *state = tunnelGetState(t);
    struct ip_hdr *iphdr = (struct ip_hdr *) sbufGetMutablePtr(buf);

    if (IPH_PROTO(iphdr) != IP_PROTO_TCP && IPH_PROTO(iphdr) != IP_PROTO_UDP)
    {
        // LOGW("PacketToConnection: Unknown IP protocol");
        goto fail;
    }

    /** Source IP address of current_header */
    ip_addr_t current_iphdr_src;
    /** Destination IP address of current_header */
    ip_addr_t current_iphdr_dest;

    /* copy IP addresses to aligned ip_addr_t */
    ipAddrCopyFromIp4(current_iphdr_dest, iphdr->dest);
    ipAddrCopyFromIp4(current_iphdr_src, iphdr->src);

    interface_route_context_t *prev = &state->route_context4;
    interface_route_context_t *cur  = state->route_context4.next;

    while (cur != NULL)
    {
        if (ip4AddrEqual(&cur->netif.ip_addr.u_addr.ip4, &current_iphdr_dest.u_addr.ip4))
        {
            break;
        }
        prev = cur;
        cur  = cur->next;
    }
    if (cur != NULL)
    {
        cur->last_tick = getTickMS();

        // move node to head if not already at head
        if (state->route_context4.next != cur)
        {
            interface_route_context_t *tmp = state->route_context4.next;
            prev->next                     = cur->next;
            state->route_context4.next     = cur;
            cur->next                      = tmp;
        }
    }
    else
    {
        LOGD("PacketTocConnection: new ip %d.%d.%d.%d", ip4_addr1(&current_iphdr_dest.u_addr.ip4),
             ip4_addr2(&current_iphdr_dest.u_addr.ip4), ip4_addr3(&current_iphdr_dest.u_addr.ip4),
             ip4_addr4(&current_iphdr_dest.u_addr.ip4));

        cur = (interface_route_context_t *) memoryAllocate(sizeof(interface_route_context_t));
        memorySet(cur, 0, sizeof(interface_route_context_t));

        cur->tcp_ports = vec_ports_t_with_capacity(16);
        cur->udp_ports = vec_ports_t_with_capacity(16);
        ip4_addr_t mask;
        IP4_ADDR(&mask, 0xFF, 0xFF, 0xFF, 0xFF);
        ip4_addr_t gw;
        IP4_ADDR(&gw, 0, 0, 0, 0);

        netif_add(&cur->netif, &current_iphdr_dest.u_addr.ip4, &mask, &gw, t, interfaceInit, ip_input);
        netif_set_up(&cur->netif);

        cur->last_tick = getTickMS();
        prev->next     = cur;
    }

    switch (IPH_PROTO(iphdr))
    {
    case IP_PROTO_TCP: {
        struct tcp_hdr *tcphdr = (struct tcp_hdr *) ((u8_t *) iphdr + IPH_HL_BYTES(iphdr));
        // no need to do anything for packets that are not SYN
        if (TCPH_FLAGS(tcphdr) != TCP_SYN)
        {
            goto tostack;
        }

        uint16_t dest_port = lwip_ntohs(tcphdr->dest);

        if (vec_ports_t_find(&cur->tcp_ports, dest_port).ref == vec_ports_t_end(&cur->tcp_ports).ref)
        {
            vec_ports_t_push_back(&cur->tcp_ports, dest_port);
            LOGD("PacketTocConnection: new tcp port %d", dest_port);

            struct tcp_pcb *pcb;

            // Create a new TCP protocol control block.

            pcb = tcp_new();
            if (pcb == NULL)
            {
                LOGW("PacketToConnection: tcp_new failed");
                goto fail;
            }

            // Bind the PCB to all available IP addresses at TCP_PORT.
            if (tcp_bind(pcb, &current_iphdr_dest, dest_port) != ERR_OK)
            {
                tcp_close(pcb);

                LOGW("PacketToConnection: tcp_bind failed");
                goto fail;
            }
            pcb->netif_idx    = netif_get_index(&cur->netif);
            pcb->callback_arg = t;
            // Start listening for incoming connections.
            pcb = tcp_listen(pcb);
            // Set the accept callback.
            tcp_accept(pcb, lwipThreadPtcTcpAccptCallback);
        }
    }

    break;

    case IP_PROTO_UDP: {
        struct udp_hdr *udphdr    = (struct udp_hdr *) ((u8_t *) iphdr + IPH_HL_BYTES(iphdr));
        uint16_t        dest_port = lwip_ntohs(udphdr->dest);
        if (vec_ports_t_find(&cur->udp_ports, dest_port).ref == vec_ports_t_end(&cur->udp_ports).ref)
        {
            vec_ports_t_push_back(&cur->udp_ports, dest_port);
            LOGD("PacketTocConnection: new udp port %d", dest_port);
            struct udp_pcb *pcb;
            // Create a new TCP protocol control block.

            pcb = udp_new();
            if (pcb == NULL)
            {
                LOGW("PacketToConnection: udp_new failed");
                goto fail;
            }

            // Bind the PCB to all available IP addresses at TCP_PORT.
            if (udp_bind(pcb, &current_iphdr_dest, dest_port) != ERR_OK)
            {
                udp_remove(pcb);

                LOGW("PacketToConnection: udp_bind failed");
                goto fail;
            }
            pcb->netif_idx = netif_get_index(&cur->netif);

            udp_recv(pcb, ptcUdpReceived, t);
        }
    }

    break;

    case IP_PROTO_ICMP: {
        // LOGW("PacketToConnection: ICMP packet is not supported");
        goto fail;
    }
    break;

    default:
        // LOGW("PacketToConnection: Unknown IP protocol");
        goto fail;
        break;
    }

tostack:
    passToTcpIp(buf, lineGetWID(l), &cur->netif);

    return;
fail:
    bufferpoolReuseBuffer(getWorkerBufferPool(lineGetWID(l)), buf);
}

void ptcTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{

    struct ip_hdr *iphdr = (struct ip_hdr *) sbufGetMutablePtr(buf);

    if (IPH_V(iphdr) == 4)
    {
        // LOGW("PacketToConnection: Only IPv4 is supported");
        LOCK_TCPIP_CORE();

        processV4(t, l, buf);

        UNLOCK_TCPIP_CORE();
    }
    else
    {
        // sad ipv6 packet
        bufferpoolReuseBuffer(getWorkerBufferPool(lineGetWID(l)), buf);
    }
}
