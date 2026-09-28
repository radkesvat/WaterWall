# PCB-lifetime port occupancy and shared generated packet identifiers.
function(ww_apply_lwip_ports_patch lwip_dir)
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[#include "lwip/opt.h"]=]
[=[#include "lwip/opt.h"
#if WW_LWIP_WORKER_ENGINES
#include "port_registry.h"
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[#include "lwip/opt.h"]=]
[=[#include "lwip/opt.h"
#if WW_LWIP_WORKER_ENGINES
#include "port_registry.h"
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[#include "lwip/opt.h"]=]
[=[#include "lwip/opt.h"
#if WW_LWIP_WORKER_ENGINES
#include "port_registry.h"
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/ip4.c"
[=[#include "lwip/opt.h"]=]
[=[#include "lwip/opt.h"
#if WW_LWIP_WORKER_ENGINES
#include "port_registry.h"
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/ip6_frag.c"
[=[#include "lwip/opt.h"]=]
[=[#include "lwip/opt.h"
#if WW_LWIP_WORKER_ENGINES
#include "port_registry.h"
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/ip.h"
[=[#define WW_LWIP_IP_OWNER void *ww_engine;]=]
[=[#define WW_LWIP_IP_OWNER void *ww_engine; u16_t ww_tracked_port;]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[
tcp_new_port(void)
{
  u8_t i;
  u16_t n = 0;
  struct tcp_pcb *pcb;

again:
  ww_ctx_tcp_port++;
  if (ww_ctx_tcp_port == TCP_LOCAL_PORT_RANGE_END) {
    ww_ctx_tcp_port = TCP_LOCAL_PORT_RANGE_START;
  }
  /* Check all PCB lists. */
  for (i = 0; i < NUM_TCP_PCB_LISTS; i++) {
    for (pcb = *tcp_pcb_lists[i]; pcb != NULL; pcb = pcb->next) {
      if (pcb->local_port == ww_ctx_tcp_port) {
        n++;
        if (n > (TCP_LOCAL_PORT_RANGE_END - TCP_LOCAL_PORT_RANGE_START)) {
          return 0;
        }
        goto again;
      }
    }
  }
  return ww_ctx_tcp_port;
}]=]
[=[
tcp_new_port(void)
{
#if WW_LWIP_WORKER_ENGINES
  return wwLwipPortAllocate(kWwLwipTcp, TCP_LOCAL_PORT_RANGE_START, TCP_LOCAL_PORT_RANGE_END - 1U);
#else
  u8_t i;
  u16_t n = 0;
  struct tcp_pcb *pcb;

again:
  ww_ctx_tcp_port++;
  if (ww_ctx_tcp_port == TCP_LOCAL_PORT_RANGE_END) {
    ww_ctx_tcp_port = TCP_LOCAL_PORT_RANGE_START;
  }
  /* Check all PCB lists. */
  for (i = 0; i < NUM_TCP_PCB_LISTS; i++) {
    for (pcb = *tcp_pcb_lists[i]; pcb != NULL; pcb = pcb->next) {
      if (pcb->local_port == ww_ctx_tcp_port) {
        n++;
        if (n > (TCP_LOCAL_PORT_RANGE_END - TCP_LOCAL_PORT_RANGE_START)) {
          return 0;
        }
        goto again;
      }
    }
  }
  return ww_ctx_tcp_port;
#endif
}]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[  ww_ctx_tcp_port = TCP_ENSURE_LOCAL_PORT_RANGE(LWIP_RAND());]=]
[=[#if !WW_LWIP_WORKER_ENGINES
  ww_ctx_tcp_port = TCP_ENSURE_LOCAL_PORT_RANGE(LWIP_RAND());
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[
tcp_bind(struct tcp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port)
{]=]
[=[
tcp_bind(struct tcp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port)
{
#if WW_LWIP_WORKER_ENGINES
  u8_t ww_port_reserved = 0;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[    port = tcp_new_port();]=]
[=[    port = tcp_new_port();
#if WW_LWIP_WORKER_ENGINES
    ww_port_reserved = port != 0;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[done:
  pcb->local_port = port;]=]
[=[done:
#if WW_LWIP_WORKER_ENGINES
  wwLwipPortCommit(kWwLwipTcp, &pcb->ww_tracked_port, port, ww_port_reserved != 0);
#endif
  pcb->local_port = port;]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[  memp_free(MEMP_TCP_PCB, pcb);]=]
[=[#if WW_LWIP_WORKER_ENGINES
  wwLwipPortRelease(kWwLwipTcp, &pcb->ww_tracked_port);
#endif
  memp_free(MEMP_TCP_PCB, pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[
udp_new_port(void)
{
  u16_t n = 0;
  struct udp_pcb *pcb;

again:
  if (ww_ctx_udp_port++ == UDP_LOCAL_PORT_RANGE_END) {
    ww_ctx_udp_port = UDP_LOCAL_PORT_RANGE_START;
  }
  /* Check all PCBs. */
  for (pcb = udp_pcbs; pcb != NULL; pcb = pcb->next) {
    if (pcb->local_port == ww_ctx_udp_port) {
      if (++n > (UDP_LOCAL_PORT_RANGE_END - UDP_LOCAL_PORT_RANGE_START)) {
        return 0;
      }
      goto again;
    }
  }
  return ww_ctx_udp_port;
}]=]
[=[
udp_new_port(void)
{
#if WW_LWIP_WORKER_ENGINES
  return wwLwipPortAllocate(kWwLwipUdp, UDP_LOCAL_PORT_RANGE_START, UDP_LOCAL_PORT_RANGE_END);
#else
  u16_t n = 0;
  struct udp_pcb *pcb;

again:
  if (ww_ctx_udp_port++ == UDP_LOCAL_PORT_RANGE_END) {
    ww_ctx_udp_port = UDP_LOCAL_PORT_RANGE_START;
  }
  /* Check all PCBs. */
  for (pcb = udp_pcbs; pcb != NULL; pcb = pcb->next) {
    if (pcb->local_port == ww_ctx_udp_port) {
      if (++n > (UDP_LOCAL_PORT_RANGE_END - UDP_LOCAL_PORT_RANGE_START)) {
        return 0;
      }
      goto again;
    }
  }
  return ww_ctx_udp_port;
#endif
}]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[  ww_ctx_udp_port = UDP_ENSURE_LOCAL_PORT_RANGE(LWIP_RAND());]=]
[=[#if !WW_LWIP_WORKER_ENGINES
  ww_ctx_udp_port = UDP_ENSURE_LOCAL_PORT_RANGE(LWIP_RAND());
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[
udp_bind(struct udp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port)
{]=]
[=[
udp_bind(struct udp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port)
{
#if WW_LWIP_WORKER_ENGINES
  u8_t ww_port_reserved = 0;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[    port = udp_new_port();]=]
[=[    port = udp_new_port();
#if WW_LWIP_WORKER_ENGINES
    ww_port_reserved = port != 0;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[done:
  pcb->local_port = port;]=]
[=[done:
#if WW_LWIP_WORKER_ENGINES
  wwLwipPortCommit(kWwLwipUdp, &pcb->ww_tracked_port, port, ww_port_reserved != 0);
#endif
  pcb->local_port = port;]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[  memp_free(MEMP_UDP_PCB, pcb);]=]
[=[#if WW_LWIP_WORKER_ENGINES
  wwLwipPortRelease(kWwLwipUdp, &pcb->ww_tracked_port);
#endif
  memp_free(MEMP_UDP_PCB, pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[  memp_free(MEMP_TCP_PCB_LISTEN, pcb);]=]
[=[#if WW_LWIP_WORKER_ENGINES
  wwLwipPortRelease(kWwLwipTcp, &pcb->ww_tracked_port);
#endif
  memp_free(MEMP_TCP_PCB_LISTEN, pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[  lpcb->local_port = pcb->local_port;]=]
[=[  lpcb->local_port = pcb->local_port;
#if WW_LWIP_WORKER_ENGINES
  lpcb->ww_tracked_port = pcb->ww_tracked_port;
  pcb->ww_tracked_port = 0;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[    npcb->local_port = ww_ctx_tcphdr->dest;]=]
[=[    npcb->local_port = ww_ctx_tcphdr->dest;
#if WW_LWIP_WORKER_ENGINES
    wwLwipPortCommit(kWwLwipTcp, &npcb->ww_tracked_port, npcb->local_port, false);
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[          npcb->local_port = dest;]=]
[=[          npcb->local_port = dest;
#if WW_LWIP_WORKER_ENGINES
          wwLwipPortCommit(kWwLwipUdp, &npcb->ww_tracked_port, dest, false);
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[          pcb->local_port = dest;]=]
[=[          pcb->local_port = dest;
#if WW_LWIP_WORKER_ENGINES
          wwLwipPortCommit(kWwLwipUdp, &pcb->ww_tracked_port, dest, false);
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[    pcb->local_port = tcp_new_port();]=]
[=[    pcb->local_port = tcp_new_port();
#if WW_LWIP_WORKER_ENGINES
    if (pcb->local_port != 0) {
      wwLwipPortCommit(kWwLwipTcp, &pcb->ww_tracked_port, pcb->local_port, true);
    }
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[    tcp_output(pcb);
  }
  return ret;]=]
[=[    tcp_output(pcb);
  }
#if WW_LWIP_WORKER_ENGINES
  else if (old_local_port == 0) {
    wwLwipPortRelease(kWwLwipTcp, &pcb->ww_tracked_port);
    pcb->local_port = 0;
  }
#endif
  return ret;]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/ip4.c"
[=[    IPH_ID_SET(iphdr, lwip_htons(ww_ctx_ip_id));]=]
[=[#if WW_LWIP_WORKER_ENGINES
    IPH_ID_SET(iphdr, lwip_htons(wwLwipNextIpv4Id()));
#else
    IPH_ID_SET(iphdr, lwip_htons(ww_ctx_ip_id));
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/ip4.c"
[=[    ++ww_ctx_ip_id;]=]
[=[#if !WW_LWIP_WORKER_ENGINES
    ++ww_ctx_ip_id;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/ip6_frag.c"
[=[  ww_ctx_identification++;]=]
[=[#if WW_LWIP_WORKER_ENGINES
  const u32_t ww_output_identification = wwLwipNextIpv6Id();
#else
  ww_ctx_identification++;
  const u32_t ww_output_identification = ww_ctx_identification;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/ip6_frag.c"
[=[    frag_hdr->_identification = lwip_htonl(ww_ctx_identification);]=]
[=[    frag_hdr->_identification = lwip_htonl(ww_output_identification);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[  pcb->local_port = src_port;]=]
[=[#if WW_LWIP_WORKER_ENGINES
  u16_t ww_temporary_port = 0;
  if (src_port == 0) {
    ww_temporary_port = wwLwipPortAllocate(kWwLwipUdp, UDP_LOCAL_PORT_RANGE_START, UDP_LOCAL_PORT_RANGE_END);
    if (ww_temporary_port == 0) {
      ip_addr_set_ipaddr(&pcb->local_ip, &addr);
      return ERR_USE;
    }
    src_port = ww_temporary_port;
  }
#endif
  pcb->local_port = src_port;]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[  pcb->local_port = port;

  return err;]=]
[=[  pcb->local_port = port;
#if WW_LWIP_WORKER_ENGINES
  wwLwipPortRelease(kWwLwipUdp, &ww_temporary_port);
#endif
  return err;]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[udp_input(struct pbuf *p, struct netif *inp)
{]=]
[=[udp_input(struct pbuf *p, struct netif *inp)
{
  u8_t ww_pretend_attempted = 0;]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[  } else {
    for (pcb = udp_pcbs; pcb != NULL; pcb = pcb->next) {
      if ((pcb->pretend_netif_idx != NETIF_NO_INDEX)]=]
[=[  } else {
    /* The accept callback may refuse/remove its child. Redispatch may find an
       installed child, but must never repeat acceptance for this same packet. */
    if (ww_pretend_attempted) {
      pbuf_free(p);
      goto end;
    }
    ww_pretend_attempted = 1;
    for (pcb = udp_pcbs; pcb != NULL; pcb = pcb->next) {
      if ((pcb->pretend_netif_idx != NETIF_NO_INDEX)]=])
endfunction()
