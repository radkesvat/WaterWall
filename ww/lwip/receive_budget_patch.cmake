# Keep protocol receive credit intact while bounding future advertisements by an
# owner-engine fair-share target. Previously announced right edges drain normally.
function(ww_apply_lwip_receive_budget_patch lwip_dir)
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/tcp.h"
[=[  u8_t ww_rcv_advertised_valid;]=]
[=[  u8_t ww_rcv_advertised_valid;
  struct tcp_pcb *ww_receive_next;
  struct tcp_pcb **ww_receive_previous;
  /* Sticky: rcv_ann_right_edge becomes a successfully committed logical edge. */
  u8_t ww_receive_limited;]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/priv/tcp_priv.h"
[=[int wwLwipEngineDeferAck(struct tcp_pcb *pcb);]=]
[=[u32_t wwLwipTcpReceiveWindow(struct tcp_pcb *pcb);
void wwLwipTcpPrepareReceiveWindow(struct tcp_pcb *pcb);
void wwLwipEngineForgetReceive(struct tcp_pcb *pcb);
int wwLwipEngineDeferAck(struct tcp_pcb *pcb);]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[  LWIP_ASSERT("tcp_update_rcv_ann_wnd: invalid pcb", pcb != NULL);
  new_right_edge = pcb->rcv_nxt + pcb->rcv_wnd;

  if (TCP_SEQ_GEQ(new_right_edge, pcb->rcv_ann_right_edge + LWIP_MIN((TCP_WND / 2), pcb->mss))) {]=]
[=[#if WW_LWIP_WORKER_ENGINES
  LWIP_ASSERT("tcp_update_rcv_ann_wnd: invalid pcb", pcb != NULL);
  const tcpwnd_size_t ww_window = (tcpwnd_size_t)wwLwipTcpReceiveWindow(pcb);
  const u32_t ww_ann_right_edge = pcb->rcv_ann_right_edge;
#else
  LWIP_ASSERT("tcp_update_rcv_ann_wnd: invalid pcb", pcb != NULL);
  const tcpwnd_size_t ww_window = pcb->rcv_wnd;
  const u32_t ww_ann_right_edge = pcb->rcv_ann_right_edge;
#endif
  new_right_edge = pcb->rcv_nxt + ww_window;

  if (TCP_SEQ_GEQ(new_right_edge, ww_ann_right_edge + LWIP_MIN((TCP_WND / 2), pcb->mss))) {]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[    pcb->rcv_ann_wnd = pcb->rcv_wnd;
    return new_right_edge - pcb->rcv_ann_right_edge;]=]
[=[    pcb->rcv_ann_wnd = ww_window;
    return new_right_edge - ww_ann_right_edge;]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[    if (TCP_SEQ_GT(pcb->rcv_nxt, pcb->rcv_ann_right_edge)) {]=]
[=[    if (TCP_SEQ_GT(pcb->rcv_nxt, ww_ann_right_edge)) {]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[      u32_t new_rcv_ann_wnd = pcb->rcv_ann_right_edge - pcb->rcv_nxt;]=]
[=[      u32_t new_rcv_ann_wnd = ww_ann_right_edge - pcb->rcv_nxt;]=])
    # The fallback preserves an existing promise even when the new share is
    # smaller. rcv_wnd remains the raw credit counter used by input and close.
    ww_lwip_replace_all("${lwip_dir}/src/core/tcp.c"
[=[  wwLwipEngineCancelAck(pcb);]=]
[=[  wwLwipEngineCancelAck(pcb);
  wwLwipEngineForgetReceive(pcb);]=] 2)
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[  /* The TCP header has already been constructed, but the ackno and
   wnd fields remain. */]=]
[=[#if WW_LWIP_WORKER_ENGINES
  wwLwipTcpPrepareReceiveWindow(pcb);
#endif
  /* The TCP header has already been constructed, but the ackno and
   wnd fields remain. */]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[  LWIP_ASSERT("tcp_output_alloc_header: invalid pcb", pcb != NULL);
]=]
[=[  LWIP_ASSERT("tcp_output_alloc_header: invalid pcb", pcb != NULL);
#if WW_LWIP_WORKER_ENGINES
  wwLwipTcpPrepareReceiveWindow(pcb);
#endif
]=])
    # Preserve the logical edge across scale rounding, but publish it only after
    # actual local acceptance. SYN window fields are unscaled and may be smaller
    # than rcv_ann_wnd, so their logical promise is exactly their wire edge.
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[struct ww_tcp_advertisement {
  u32_t edge;
  u8_t valid;
};]=]
[=[struct ww_tcp_advertisement {
  u32_t edge;
  u32_t ann_edge;
  u8_t valid;
};]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[  struct ww_tcp_advertisement advertised = {0, 0};]=]
[=[  struct ww_tcp_advertisement advertised = {0, 0, 0};]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[  advertised.edge = lwip_ntohl(header->ackno) + window;
  advertised.valid = 1;]=]
[=[  advertised.edge = lwip_ntohl(header->ackno) + window;
  advertised.ann_edge = (TCPH_FLAGS(header) & TCP_SYN) != 0 ? advertised.edge :
      lwip_ntohl(header->ackno) + pcb->rcv_ann_wnd;
  advertised.valid = 1;]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[    pcb->ww_rcv_advertised_valid = 1;]=]
[=[    pcb->ww_rcv_advertised_valid = 1;
    if (pcb->ww_receive_limited) {
      pcb->rcv_ann_right_edge = advertised.ann_edge;
    }]=])
    ww_lwip_replace_all("${lwip_dir}/src/core/tcp_out.c"
[=[  pcb->rcv_ann_right_edge = pcb->rcv_nxt + pcb->rcv_ann_wnd;]=]
[=[#if WW_LWIP_WORKER_ENGINES
  if (!pcb->ww_receive_limited)
#endif
  {
    pcb->rcv_ann_right_edge = pcb->rcv_nxt + pcb->rcv_ann_wnd;
  }]=] 2)
endfunction()
