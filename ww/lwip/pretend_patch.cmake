function(ww_lwip_replace_once file before after)
    file(READ "${file}" content)
    string(FIND "${content}" "${after}" already_patched)
    if(NOT already_patched EQUAL -1)
        return()
    endif()

    string(FIND "${content}" "${before}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "Waterwall lwIP pretend patch failed for ${file}")
    endif()

    string(LENGTH "${before}" before_len)
    string(SUBSTRING "${content}" 0 ${found} content_prefix)
    math(EXPR suffix_start "${found} + ${before_len}")
    string(SUBSTRING "${content}" ${suffix_start} -1 content_suffix)
    set(content "${content_prefix}${after}${content_suffix}")
    file(WRITE "${file}" "${content}")
endfunction()

function(ww_apply_lwip_pretend_patch lwip_dir)
    ww_lwip_replace_once(
        "${lwip_dir}/src/include/lwip/netif.h"
        [=[#define NETIF_FLAG_MLD6         0x40U

/**
 * @}
 */]=]
        [=[#define NETIF_FLAG_MLD6         0x40U
/** If set, the netif accepts TCP/UDP packets for arbitrary destination hosts.
 * This is used by tun2socks-style gateways to preserve the original destination. */
#define NETIF_FLAG_PRETEND      0x80U
#define NETIF_FLAG_PRETEND_TCP  NETIF_FLAG_PRETEND
#define NETIF_FLAG_PRETEND_UDP  NETIF_FLAG_PRETEND

/**
 * @}
 */]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/include/lwip/tcp.h"
        [=[  TCP_PCB_EXTARGS \
  enum tcp_state state; /* TCP state */ \
  u8_t prio; \
  /* ports are in host byte order */ \
  u16_t local_port]=]
        [=[  TCP_PCB_EXTARGS \
  enum tcp_state state; /* TCP state */ \
  u8_t prio; \
  u8_t pretend_netif_idx; \
  /* ports are in host byte order */ \
  u16_t local_port]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/include/lwip/udp.h"
        [=[  struct udp_pcb *next;

  u8_t flags;
  /** ports are in host byte order */
  u16_t local_port, remote_port;]=]
        [=[  struct udp_pcb *next;

  u8_t flags;
  u8_t pretend_netif_idx;
  /** ports are in host byte order */
  u16_t local_port, remote_port;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/include/lwip/udp.h"
        [=[err_t            udp_sendto_if_src(struct udp_pcb *pcb, struct pbuf *p,
                                 const ip_addr_t *dst_ip, u16_t dst_port,
                                 struct netif *netif, const ip_addr_t *src_ip);
err_t            udp_sendto     (struct udp_pcb *pcb, struct pbuf *p,]=]
        [=[err_t            udp_sendto_if_src(struct udp_pcb *pcb, struct pbuf *p,
                                 const ip_addr_t *dst_ip, u16_t dst_port,
                                 struct netif *netif, const ip_addr_t *src_ip);
err_t            udp_sendfrom   (struct udp_pcb *pcb, struct pbuf *p,
                                 const ip_addr_t *src_ip, u16_t src_port);
err_t            udp_sendto     (struct udp_pcb *pcb, struct pbuf *p,]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4.c"
        [=[ip4_input_accept(struct netif *netif)]=]
        [=[ip4_input_accept(struct netif *netif, const struct ip_hdr *iphdr)]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4.c"
        [=[#endif /* LWIP_NETIF_LOOPBACK && !LWIP_HAVE_LOOPIF */
       ) {]=]
        [=[#endif /* LWIP_NETIF_LOOPBACK && !LWIP_HAVE_LOOPIF */
        || (netif_is_flag_set(netif, NETIF_FLAG_PRETEND) &&
            ((IPH_PROTO(iphdr) == IP_PROTO_TCP) || (IPH_PROTO(iphdr) == IP_PROTO_UDP)))
       ) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4.c"
        [=[if (ip4_input_accept(inp)) {]=]
        [=[if (ip4_input_accept(inp, iphdr)) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4.c"
        [=[          if (ip4_input_accept(netif)) {]=]
        [=[          if (ip4_input_accept(netif, iphdr)) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv6/ip6.c"
        [=[ip6_input_accept(struct netif *netif)]=]
        [=[ip6_input_accept(struct netif *netif, const struct ip6_hdr *ip6hdr)]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv6/ip6.c"
        [=[  if (netif_is_up(netif)) {
    u8_t i;]=]
        [=[  if (netif_is_up(netif)) {
    u8_t i;
    if (netif_is_flag_set(netif, NETIF_FLAG_PRETEND) &&
        ((IP6H_NEXTH(ip6hdr) == IP6_NEXTH_TCP) || (IP6H_NEXTH(ip6hdr) == IP6_NEXTH_UDP))) {
      return 1;
    }]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv6/ip6.c"
        [=[if (ip6_input_accept(inp)) {]=]
        [=[if (ip6_input_accept(inp, ip6hdr)) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv6/ip6.c"
        [=[        if (ip6_input_accept(netif)) {]=]
        [=[        if (ip6_input_accept(netif, ip6hdr)) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[      if (pcb->local_port != 0) {
        TCP_RMV(&tcp_bound_pcbs, pcb);
      }
      tcp_free(pcb);]=]
        [=[      if ((pcb->local_port != 0) || (pcb->pretend_netif_idx != NETIF_NO_INDEX)) {
        TCP_RMV(&tcp_bound_pcbs, pcb);
      }
      tcp_free(pcb);]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[    if (pcb->state == CLOSED) {
      if (pcb->local_port != 0) {
        /* bound, not yet opened */
        TCP_RMV(&tcp_bound_pcbs, pcb);
      }]=]
        [=[    if (pcb->state == CLOSED) {
      if ((pcb->local_port != 0) || (pcb->pretend_netif_idx != NETIF_NO_INDEX)) {
        /* bound, not yet opened */
        TCP_RMV(&tcp_bound_pcbs, pcb);
      }]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[  LWIP_ASSERT_CORE_LOCKED();

#if LWIP_IPV4]=]
        [=[  LWIP_ASSERT_CORE_LOCKED();

  if ((ipaddr == NULL) && (port == 0) && (pcb->netif_idx != NETIF_NO_INDEX)) {
    /* Check if the pretend binding is already in use. */
    for (i = 0; i < NUM_TCP_PCB_LISTS; i++) {
      for (cpcb = *tcp_pcb_lists[i]; cpcb; cpcb = cpcb->next) {
        if (cpcb->pretend_netif_idx == pcb->netif_idx) {
          return ERR_USE;
        }
      }
    }

    struct netif *netif = netif_get_by_index(pcb->netif_idx);
    if (netif_is_flag_set(netif, NETIF_FLAG_PRETEND_TCP)) {
      pcb->pretend_netif_idx = pcb->netif_idx;
      goto done;
    }
  }

#if LWIP_IPV4]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[  pcb->local_port = port;
  TCP_REG(&tcp_bound_pcbs, pcb);]=]
        [=[done:
  pcb->local_port = port;
  TCP_REG(&tcp_bound_pcbs, pcb);]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[  lpcb->netif_idx = pcb->netif_idx;
  lpcb->ttl = pcb->ttl;]=]
        [=[  lpcb->netif_idx = pcb->netif_idx;
  lpcb->pretend_netif_idx = pcb->pretend_netif_idx;
  lpcb->ttl = pcb->ttl;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[  if (pcb->local_port != 0) {
    TCP_RMV(&tcp_bound_pcbs, pcb);
  }]=]
        [=[  if ((pcb->local_port != 0) || (pcb->pretend_netif_idx != NETIF_NO_INDEX)) {
    TCP_RMV(&tcp_bound_pcbs, pcb);
  }]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp_in.c"
        [=[      if (lpcb->local_port == tcphdr->dest) {]=]
        [=[      if ((lpcb->pretend_netif_idx != NETIF_NO_INDEX) &&
          (lpcb->pretend_netif_idx == netif_get_index(inp))) {
        if (IP_ADDR_PCB_VERSION_MATCH(lpcb, ip_current_dest_addr())) {
          break;
        }
      } else if (lpcb->local_port == tcphdr->dest) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp_in.c"
        [=[    npcb->local_port = pcb->local_port;]=]
        [=[    npcb->local_port = tcphdr->dest;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[  pcb = NULL;
  prev = NULL;
  uncon_pcb = NULL;]=]
        [=[again:
  pcb = NULL;
  prev = NULL;
  uncon_pcb = NULL;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[    /* compare PCB local addr+port to UDP destination addr+port */]=]
        [=[    if ((pcb->pretend_netif_idx != NETIF_NO_INDEX) &&
        ((pcb->flags & UDP_FLAGS_CONNECTED) != 0)) {
      if ((pcb->remote_port == src) &&
          ip_addr_cmp(&pcb->remote_ip, ip_current_src_addr()) &&
          (pcb->local_port == dest) &&
          ip_addr_cmp(&pcb->local_ip, ip_current_dest_addr())) {
        break;
      }
      prev = pcb;
      continue;
    }

    /* compare PCB local addr+port to UDP destination addr+port */]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[                if (q != NULL) {]=]
        [=[                if ((q != NULL) && (pcb->pretend_netif_idx == NETIF_NO_INDEX)) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[        pcb->recv(pcb->recv_arg, pcb, p, ip_current_src_addr(), src);]=]
        [=[        if (pcb->pretend_netif_idx != NETIF_NO_INDEX) {
          ip_addr_set_ipaddr(&pcb->local_ip, ip_current_dest_addr());
          pcb->local_port = dest;
        }
        pcb->recv(pcb->recv_arg, pcb, p, ip_current_src_addr(), src);]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[  } else {
    pbuf_free(p);
  }
end:]=]
        [=[  } else {
    for (pcb = udp_pcbs; pcb != NULL; pcb = pcb->next) {
      if ((pcb->pretend_netif_idx != NETIF_NO_INDEX) &&
          (pcb->pretend_netif_idx == netif_get_index(inp)) &&
          ((pcb->flags & UDP_FLAGS_CONNECTED) == 0) &&
          (pcb->recv != NULL) &&
          IP_ADDR_PCB_VERSION_MATCH(pcb, ip_current_dest_addr())) {
        struct udp_pcb *npcb = udp_new_ip_type(pcb->local_ip.type);
        if (npcb != NULL) {
          ip_addr_set_ipaddr(&npcb->local_ip, ip_current_dest_addr());
          ip_addr_set_ipaddr(&npcb->remote_ip, ip_current_src_addr());
          npcb->local_port = dest;
          npcb->remote_port = src;
          npcb->flags |= UDP_FLAGS_CONNECTED;
          npcb->netif_idx = pcb->netif_idx;
          npcb->pretend_netif_idx = pcb->pretend_netif_idx;
          npcb->next = udp_pcbs;
          udp_pcbs = npcb;
          pcb->recv(pcb->recv_arg, npcb, p, ip_current_dest_addr(), dest);
          goto again;
        }
        break;
      }
    }

    pbuf_free(p);
  }
end:]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[#endif /* LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP */

/**
 * @ingroup udp_raw
 * Send data to a specified address using UDP.]=]
        [=[#endif /* LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP */

/**
 * @ingroup udp_raw
 * Send data from a specified address using UDP.
 */
err_t
udp_sendfrom(struct udp_pcb *pcb, struct pbuf *p,
             const ip_addr_t *src_ip, u16_t src_port)
{
  err_t err;
  ip_addr_t addr;
  u16_t port;

  ip_addr_set_ipaddr(&addr, &pcb->local_ip);
  port = pcb->local_port;

  ip_addr_set_ipaddr(&pcb->local_ip, src_ip);
  pcb->local_port = src_port;

  err = udp_send(pcb, p);

  ip_addr_set_ipaddr(&pcb->local_ip, &addr);
  pcb->local_port = port;

  return err;
}

/**
 * @ingroup udp_raw
 * Send data to a specified address using UDP.]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[      if (netif_get_ip6_addr_match(netif, ip_2_ip6(&pcb->local_ip)) < 0) {]=]
        [=[      if (!netif_is_flag_set(netif, NETIF_FLAG_PRETEND_UDP) &&
          netif_get_ip6_addr_match(netif, ip_2_ip6(&pcb->local_ip)) < 0) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[      if (!ip4_addr_eq(ip_2_ip4(&(pcb->local_ip)), netif_ip4_addr(netif))) {]=]
        [=[      if (!netif_is_flag_set(netif, NETIF_FLAG_PRETEND_UDP) &&
          !ip4_addr_eq(ip_2_ip4(&(pcb->local_ip)), netif_ip4_addr(netif))) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[  u8_t rebind;
#if LWIP_IPV6 && LWIP_IPV6_SCOPES]=]
        [=[  u8_t rebind = 0;
#if LWIP_IPV6 && LWIP_IPV6_SCOPES]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[  LWIP_ASSERT_CORE_LOCKED();

#if LWIP_IPV4]=]
        [=[  LWIP_ASSERT_CORE_LOCKED();

  if ((ipaddr == NULL) && (port == 0) && (pcb->netif_idx != NETIF_NO_INDEX)) {
    for (ipcb = udp_pcbs; ipcb != NULL; ipcb = ipcb->next) {
      if (ipcb->pretend_netif_idx == pcb->netif_idx) {
        return ERR_USE;
      }
    }

    struct netif *netif = netif_get_by_index(pcb->netif_idx);
    if (netif_is_flag_set(netif, NETIF_FLAG_PRETEND_UDP)) {
      pcb->pretend_netif_idx = pcb->netif_idx;
      goto done;
    }
  }

#if LWIP_IPV4]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[  rebind = 0;
  /* Check for double bind and rebind of the same pcb */]=]
        [=[  /* Check for double bind and rebind of the same pcb */]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[  pcb->local_port = port;
  mib2_udp_bind(pcb);]=]
        [=[done:
  pcb->local_port = port;
  mib2_udp_bind(pcb);]=])

    # Upstream lwIP 2.2 has no threaded shutdown API. WaterWall must stop and
    # join tcpip_thread before destroying the pseudo-worker pools that its
    # callbacks can still reach.
    ww_lwip_replace_once(
        "${lwip_dir}/src/include/lwip/tcpip.h"
        [=[void   tcpip_init(tcpip_init_done_fn tcpip_init_done, void *arg);

err_t  tcpip_inpkt]=]
        [=[void   tcpip_init(tcpip_init_done_fn tcpip_init_done, void *arg);
err_t  tcpip_shutdown(tcpip_callback_fn shutdown_fn, void *ctx);

err_t  tcpip_inpkt]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/api/tcpip.c"
        [=[static void *tcpip_init_done_arg;
static sys_mbox_t tcpip_mbox;]=]
        [=[static void *tcpip_init_done_arg;
static sys_mbox_t tcpip_mbox;
static sys_thread_t tcpip_thread_handle;
static u8_t tcpip_shutdown_requested;
static u8_t tcpip_shutdown_posted;
static tcpip_callback_fn tcpip_shutdown_fn;
static void *tcpip_shutdown_ctx;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/api/tcpip.c"
        [=[    tcpip_thread_handle_msg(msg);
  }
}]=]
        [=[    tcpip_thread_handle_msg(msg);
    if (tcpip_shutdown_requested) {
      break;
    }
  }
  UNLOCK_TCPIP_CORE();
}]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/api/tcpip.c"
        [=[  sys_thread_new(TCPIP_THREAD_NAME, tcpip_thread, NULL, TCPIP_THREAD_STACKSIZE, TCPIP_THREAD_PRIO);
}

/**
 * Simple callback function used with tcpip_callback to free a pbuf]=]
        [=[  tcpip_shutdown_requested = 0;
  tcpip_shutdown_posted = 0;
  tcpip_shutdown_fn = NULL;
  tcpip_shutdown_ctx = NULL;
  tcpip_thread_handle =
    sys_thread_new(TCPIP_THREAD_NAME, tcpip_thread, NULL, TCPIP_THREAD_STACKSIZE, TCPIP_THREAD_PRIO);
}

static void
tcpip_request_shutdown(void *ctx)
{
  LWIP_UNUSED_ARG(ctx);
  if (tcpip_shutdown_fn != NULL) {
    tcpip_shutdown_fn(tcpip_shutdown_ctx);
  }
  tcpip_shutdown_requested = 1;
}

/**
 * Cooperatively stop and join tcpip_thread after all application users have
 * detached and released their protocol state.
 */
err_t
tcpip_shutdown(tcpip_callback_fn shutdown_fn, void *ctx)
{
  err_t err;

  if (tcpip_thread_handle == NULL) {
    return ERR_OK;
  }

  if (!tcpip_shutdown_posted) {
    tcpip_shutdown_fn = shutdown_fn;
    tcpip_shutdown_ctx = ctx;
    err = tcpip_callback(tcpip_request_shutdown, NULL);
    if (err != ERR_OK) {
      tcpip_shutdown_fn = NULL;
      tcpip_shutdown_ctx = NULL;
      return err;
    }
    tcpip_shutdown_posted = 1;
  }
  if (!sys_thread_join(tcpip_thread_handle)) {
    return ERR_IF;
  }

  tcpip_thread_handle = NULL;
  tcpip_shutdown_posted = 0;
  tcpip_shutdown_fn = NULL;
  tcpip_shutdown_ctx = NULL;
  sys_mbox_free(&tcpip_mbox);
#if LWIP_TCPIP_CORE_LOCKING
  sys_mutex_free(&lock_tcpip_core);
#endif
  return ERR_OK;
}

/**
 * Simple callback function used with tcpip_callback to free a pbuf]=])
endfunction()
