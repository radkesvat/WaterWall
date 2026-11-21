# A PCB bound to a netif sends through that netif whatever the route table says
# (tcp_route), so its effective send MSS has to come from that netif's MTU too.
# lwIP asks ip_route() when the handshake completes; a netif that owns a single
# /32 address without a default route, as ConnectionToPackets' does, is not found
# there, the peer's larger MSS is kept, and every full segment then leaves as two
# IP fragments.
function(ww_apply_lwip_tcp_bound_mss_patch lwip_dir)
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[    npcb->mss = tcp_eff_send_mss(npcb->mss, &npcb->local_ip, &npcb->remote_ip);]=]
[=[    npcb->mss = tcp_eff_send_mss_netif(npcb->mss,
                                       (npcb->netif_idx != NETIF_NO_INDEX) ? netif_get_by_index(npcb->netif_idx) :
                                       ip_route(&npcb->local_ip, &npcb->remote_ip),
                                       &npcb->remote_ip);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[        pcb->mss = tcp_eff_send_mss(pcb->mss, &pcb->local_ip, &pcb->remote_ip);]=]
[=[        pcb->mss = tcp_eff_send_mss_netif(pcb->mss,
                                          (pcb->netif_idx != NETIF_NO_INDEX) ? netif_get_by_index(pcb->netif_idx) :
                                          ip_route(&pcb->local_ip, &pcb->remote_ip),
                                          &pcb->remote_ip);]=])
endfunction()
