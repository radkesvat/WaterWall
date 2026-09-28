function(ww_apply_lwip_timer_patch lwip_dir)
    ww_lwip_replace_once("${lwip_dir}/src/core/timeouts.c"
[=[sys_check_timeouts(void)
{]=]
[=[sys_check_timeouts(void)
{
#if WW_LWIP_WORKER_ENGINES
  unsigned ww_dispatched = 0;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/timeouts.c"
[=[    PBUF_CHECK_FREE_OOSEQ();]=]
[=[#if WW_LWIP_WORKER_ENGINES
    /* A callback can schedule another immediately due timeout. Bound each
       dispatch even in that case and let the owner loop schedule a new wake. */
    if (ww_dispatched++ == MEMP_NUM_SYS_TIMEOUT) {
      return;
    }
#endif
    PBUF_CHECK_FREE_OOSEQ();]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/netif.c"
[=[netif_poll(struct netif *netif)
{]=]
[=[netif_poll(struct netif *netif)
{
#if WW_LWIP_WORKER_ENGINES
  unsigned ww_polled = 0;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/netif.c"
[=[  while (netif->loop_first != NULL) {
    struct pbuf *in, *in_end;]=]
[=[  while (netif->loop_first != NULL) {
    struct pbuf *in, *in_end;
#if WW_LWIP_WORKER_ENGINES
    /* Replies can enqueue more loopback input. Yield after a bounded batch;
       the engine's next deadline includes any remaining loopback queue. */
    if (ww_polled++ == LWIP_LOOPBACK_MAX_PBUFS) {
      break;
    }
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/netif.c"
[=[  mib2_netif_removed(netif);]=]
[=[#if WW_LWIP_WORKER_ENGINES && ENABLE_LOOPBACK
  /* No threaded loopback callback exists in a worker engine. Settle queued
     packets before the removal callback can release the embedded netif. */
  if (netif->loop_first != NULL) {
    struct pbuf *queued = netif->loop_first;
    netif->loop_first = netif->loop_last = NULL;
    netif->loop_cnt_current = 0;
    pbuf_free(queued);
  }
#endif
  mib2_netif_removed(netif);]=])
endfunction()
