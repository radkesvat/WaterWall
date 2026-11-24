# A PCB bound to a netif sends through that netif whatever the route table says
# (tcp_route), so its effective send MSS has to come from that netif's MTU too.
# lwIP asks ip_route() when the handshake completes; a netif that owns a single
# /32 address without a default route, as ConnectionToPackets' does, is not found
# there, the peer's larger MSS is kept, and every full segment then leaves as two
# IP fragments.
function(ww_apply_lwip_tcp_bound_mss_patch lwip_dir)
    set(tcp_in "${lwip_dir}/src/core/tcp_in.c")

    # Option parsing also runs on retransmissions and established connections.
    # Return the peer's offer to the handshake that will adopt it. A duplicate SYN
    # must not overwrite the effective MSS already chosen for a passive connection.
    ww_lwip_replace_all("${tcp_in}"
        "tcp_parseopt(struct tcp_pcb *pcb)"
        "tcp_parseopt(struct tcp_pcb *pcb, u16_t *peer_mss)" 2)
    ww_lwip_replace_once("${tcp_in}"
        "          pcb->mss = ((mss > TCP_MSS) || (mss == 0)) ? TCP_MSS : mss;"
        "          *peer_mss = ((mss > TCP_MSS) || (mss == 0)) ? TCP_MSS : mss;")

    ww_lwip_replace_once("${tcp_in}"
        "    tcp_parseopt(npcb);"
        "    tcp_parseopt(npcb, &npcb->mss);")
    ww_lwip_replace_once("${tcp_in}"
[=[    npcb->mss = tcp_eff_send_mss(npcb->mss, &npcb->local_ip, &npcb->remote_ip);]=]
[=[    npcb->mss = tcp_eff_send_mss_netif(npcb->mss,
                                       (npcb->netif_idx != NETIF_NO_INDEX) ? netif_get_by_index(npcb->netif_idx) :
                                       ip_route(&npcb->local_ip, &npcb->remote_ip),
                                       &npcb->remote_ip);]=])

    ww_lwip_replace_once("${tcp_in}"
        "  struct tcp_seg *rseg;"
        "  struct tcp_seg *rseg;\n  u16_t peer_mss;")
    ww_lwip_replace_once("${tcp_in}"
        "  tcp_parseopt(pcb);"
[=[  peer_mss = pcb->mss;
  tcp_parseopt(pcb, &peer_mss);]=])
    ww_lwip_replace_once("${tcp_in}"
[=[        pcb->mss = tcp_eff_send_mss(pcb->mss, &pcb->local_ip, &pcb->remote_ip);
#endif /* TCP_CALCULATE_EFF_SEND_MSS */]=]
[=[        pcb->mss = tcp_eff_send_mss_netif(peer_mss,
                                          (pcb->netif_idx != NETIF_NO_INDEX) ? netif_get_by_index(pcb->netif_idx) :
                                          ip_route(&pcb->local_ip, &pcb->remote_ip),
                                          &pcb->remote_ip);
#else
        pcb->mss = peer_mss;
#endif /* TCP_CALCULATE_EFF_SEND_MSS */]=])
endfunction()
