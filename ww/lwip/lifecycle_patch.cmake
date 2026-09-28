function(ww_apply_lwip_lifecycle_patch lwip_dir)
    ww_lwip_replace_once("${lwip_dir}/src/core/netif.c"
[=[#include "lwip/netif.h"]=]
[=[#include "lwip/netif.h"
#include "lwip/mem.h"]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/dhcp.c"
[=[  dhcp = netif_dhcp_data(netif);
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_start(netif=]=]
[=[  dhcp = netif_dhcp_data(netif);
  const u8_t ww_external = dhcp != NULL ? (dhcp->flags & DHCP_FLAG_EXTERNAL_MEM) : 0;
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_start(netif=]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/dhcp.c"
[=[  memset(dhcp, 0, sizeof(struct dhcp));
  /* dhcp_set_state(&dhcp, DHCP_STATE_OFF); */]=]
[=[  memset(dhcp, 0, sizeof(struct dhcp));
  dhcp->flags = ww_external;
  /* dhcp_set_state(&dhcp, DHCP_STATE_OFF); */]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/autoip.h"
[=[struct autoip
{]=]
[=[struct autoip
{
  u8_t ww_heap_owned;]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/autoip.c"
[=[    /* store this AutoIP client in the netif */]=]
[=[    autoip->ww_heap_owned = 1;
    /* store this AutoIP client in the netif */]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/netif.c"
[=[void
netif_remove(struct netif *netif)]=]
[=[/* Release address-management storage before its shared UDP PCB is reclaimed.
 * Caller-provided DHCP/AutoIP storage remains caller-owned. */
void
wwLwipNetifProtocolCleanup(struct netif *netif)
{
  WW_LWIP_ASSERT_NETIF_OWNER(netif);
#if LWIP_DHCP
  dhcp_release_and_stop(netif);
  dhcp_cleanup(netif);
#endif
#if LWIP_AUTOIP
  struct autoip *autoip = netif_autoip_data(netif);
  if (autoip != NULL) {
    autoip_stop(netif);
    acd_remove(netif, &autoip->acd);
    netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_AUTOIP, NULL);
    if (autoip->ww_heap_owned) {
      mem_free(autoip);
    }
  }
#endif
}

void
netif_remove(struct netif *netif)]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/netif.c"
[=[  tcp_netif_removed(netif);]=]
[=[  wwLwipNetifProtocolCleanup(netif);
  tcp_netif_removed(netif);]=])
    ww_lwip_replace_once("${lwip_dir}/src/netif/lowpan6.c"
[=[void
lowpan6_tmr(void)]=]
[=[void
wwLwipLowpanCleanup(void)
{
  while (ww_ctx_lowpan6_data.reass_list != NULL) {
    struct lowpan6_reass_helper *head = ww_ctx_lowpan6_data.reass_list;
    dequeue_datagram(head, NULL);
    free_reass_datagram(head);
  }
}

void
lowpan6_tmr(void)]=])
endfunction()
