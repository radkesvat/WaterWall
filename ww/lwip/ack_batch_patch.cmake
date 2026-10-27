# Queue ordinary ACK intent before packet construction, only for an explicit
# bounded receive batch. Gap-recovery progress requests an immediate ACK;
# control sends and the normal delayed-ACK timer retain their upstream behavior.
function(ww_apply_lwip_ack_batch_patch lwip_dir)
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/tcp.h"
[=[  TCP_PCB_COMMON(struct tcp_pcb);

  /* ports are in host byte order */]=]
[=[  TCP_PCB_COMMON(struct tcp_pcb);

#if WW_LWIP_WORKER_ENGINES
  /* Intrusive ordinary-ACK intent; detached before purge/free or batch output. */
  struct tcp_pcb *ww_ack_next;
  struct tcp_pcb **ww_ack_previous;
  /* Right edge of the last non-RST ACK accepted by local output. */
  u32_t ww_rcv_advertised_edge;
  u8_t ww_rcv_advertised_valid;
#endif

  /* ports are in host byte order */]=])

    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/priv/tcp_priv.h"
[=[#define tcp_ack(pcb)]=]
[=[#if WW_LWIP_WORKER_ENGINES
int wwLwipEngineDeferAck(struct tcp_pcb *pcb);
void wwLwipEngineCancelAck(struct tcp_pcb *pcb);
#endif

#define tcp_ack(pcb)]=])

    # Capture eligibility before duplicate trimming or filling an out-of-order
    # gap changes the input/PCB into an apparently ordinary in-order segment.
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[tcp_receive(struct tcp_pcb *pcb)
{
  s16_t m;
  u32_t right_wnd_edge;
]=]
[=[tcp_receive(struct tcp_pcb *pcb)
{
  s16_t m;
  u32_t right_wnd_edge;
#if WW_LWIP_WORKER_ENGINES
  u8_t ww_ack_batch_eligible = pcb->state == ESTABLISHED &&
      ww_ctx_seqno == pcb->rcv_nxt && ww_ctx_inseg.len != 0 &&
      (ww_ctx_flags & ~(TCP_ACK | TCP_PSH)) == 0;
#if TCP_QUEUE_OOSEQ
  u32_t ww_rcv_nxt_before = pcb->rcv_nxt;
  u8_t ww_gap_pending = pcb->ooseq != NULL && ww_ctx_inseg.len != 0;
  ww_ack_batch_eligible = ww_ack_batch_eligible && pcb->ooseq == NULL;
#endif
#endif
]=])

    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[        /* Acknowledge the segment(s). */
        tcp_ack(pcb);]=]
[=[        /* Acknowledge the segment(s). */
#if WW_LWIP_WORKER_ENGINES
#if TCP_QUEUE_OOSEQ
        if (ww_gap_pending && TCP_SEQ_GT(pcb->rcv_nxt, ww_rcv_nxt_before)) {
          tcp_ack_now(pcb);
        } else
#endif
        if (!ww_ack_batch_eligible || !wwLwipEngineDeferAck(pcb))
#endif
        {
          tcp_ack(pcb);
        }]=])

    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[tcp_recved(struct tcp_pcb *pcb, u16_t len)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);
  u32_t wnd_inflation;
  tcpwnd_size_t rcv_wnd;]=]
[=[tcp_recved_credit(struct tcp_pcb *pcb, u32_t len)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);
  u32_t wnd_inflation;
  u32_t rcv_wnd;
#if WW_LWIP_WORKER_ENGINES
  u8_t ww_window_was_open;
#endif]=])

    # The standard API remains 16-bit. A bridge's one aggregated receive
    # delivery can exceed that width; return it atomically so its final window
    # is advertised once rather than after every artificial 65,535-byte chunk.
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[void
tcp_recved_credit(struct tcp_pcb *pcb, u32_t len)]=]
[=[static void
tcp_recved_credit(struct tcp_pcb *pcb, u32_t len)]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[  rcv_wnd = (tcpwnd_size_t)(pcb->rcv_wnd + len);]=]
[=[  rcv_wnd = pcb->rcv_wnd + len;]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[    pcb->rcv_wnd = rcv_wnd;]=]
[=[    pcb->rcv_wnd = (tcpwnd_size_t)rcv_wnd;]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[  LWIP_DEBUGF(TCP_DEBUG, ("tcp_recved: received %"U16_F" bytes, wnd %"TCPWNDSIZE_F" (%"TCPWNDSIZE_F").\n",
                          len, pcb->rcv_wnd, (u16_t)(TCP_WND_MAX(pcb) - pcb->rcv_wnd)));
}]=]
[=[  LWIP_DEBUGF(TCP_DEBUG, ("tcp_recved: received %"U32_F" bytes, wnd %"TCPWNDSIZE_F" (%"TCPWNDSIZE_F").\n",
                          len, pcb->rcv_wnd, (u16_t)(TCP_WND_MAX(pcb) - pcb->rcv_wnd)));
}

void
tcp_recved(struct tcp_pcb *pcb, u16_t len)
{
  tcp_recved_credit(pcb, len);
}

#if WW_LWIP_WORKER_ENGINES
void
wwLwipTcpRecved(struct tcp_pcb *pcb, uint32_t len)
{
  tcp_recved_credit(pcb, len);
}
#endif]=])

    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[  LWIP_ERROR("tcp_recved: invalid pcb", pcb != NULL, return);
]=]
[=[  LWIP_ERROR("tcp_recved: invalid pcb", pcb != NULL, return);
#if WW_LWIP_WORKER_ENGINES
  ww_window_was_open = pcb->ww_rcv_advertised_valid &&
      TCP_SEQ_GT(pcb->ww_rcv_advertised_edge, pcb->rcv_nxt);
#endif
]=])

    # Record the constructed wire window, not the intended unquantized window.
    # Snapshot before IP output can prepend headers or release a control pbuf.
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[/**
 * Called by tcp_output() to actually send a TCP segment over IP.]=]
[=[#if WW_LWIP_WORKER_ENGINES
struct ww_tcp_advertisement {
  u32_t edge;
  u8_t valid;
};

static struct ww_tcp_advertisement
ww_tcp_capture_advertisement(const struct tcp_pcb *pcb, const struct tcp_hdr *header)
{
  struct ww_tcp_advertisement advertised = {0, 0};
  u32_t window;
  if ((pcb == NULL) || ((TCPH_FLAGS(header) & (TCP_ACK | TCP_RST)) != TCP_ACK)) {
    return advertised;
  }
  window = lwip_ntohs(header->wnd);
#if LWIP_WND_SCALE
  if (((TCPH_FLAGS(header) & TCP_SYN) == 0) && ((pcb->flags & TF_WND_SCALE) != 0)) {
    window <<= pcb->rcv_scale;
  }
#endif
  advertised.edge = lwip_ntohl(header->ackno) + window;
  advertised.valid = 1;
  return advertised;
}

static void
ww_tcp_commit_advertisement(struct tcp_pcb *pcb, struct ww_tcp_advertisement advertised, err_t err)
{
  if (advertised.valid && (err == ERR_OK)) {
    pcb->ww_rcv_advertised_edge = advertised.edge;
    pcb->ww_rcv_advertised_valid = 1;
    /* A successful control/piggyback ACK also satisfies queued ACK intent. */
    tcp_clear_flags(pcb, TF_ACK_DELAY | TF_ACK_NOW);
  }
}
#endif

/**
 * Called by tcp_output() to actually send a TCP segment over IP.]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[  NETIF_SET_HINTS(netif, &(pcb->netif_hints));
  err = ip_output_if(seg->p, &pcb->local_ip, &pcb->remote_ip, pcb->ttl,
                     pcb->tos, IP_PROTO_TCP, netif);
  NETIF_RESET_HINTS(netif);]=]
[=[#if WW_LWIP_WORKER_ENGINES
  const struct ww_tcp_advertisement ww_advertised = ww_tcp_capture_advertisement(pcb, seg->tcphdr);
#endif
  NETIF_SET_HINTS(netif, &(pcb->netif_hints));
  err = ip_output_if(seg->p, &pcb->local_ip, &pcb->remote_ip, pcb->ttl,
                     pcb->tos, IP_PROTO_TCP, netif);
  NETIF_RESET_HINTS(netif);
#if WW_LWIP_WORKER_ENGINES
  ww_tcp_commit_advertisement(pcb, ww_advertised, err);
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[  TCP_STATS_INC(tcp.xmit);
  err = ip_output_if(p, src, dst, ttl, tos, IP_PROTO_TCP, netif);
  NETIF_RESET_HINTS(netif);]=]
[=[#if WW_LWIP_WORKER_ENGINES
  const struct ww_tcp_advertisement ww_advertised =
      ww_tcp_capture_advertisement(pcb, (const struct tcp_hdr *)p->payload);
#endif
  TCP_STATS_INC(tcp.xmit);
  err = ip_output_if(p, src, dst, ttl, tos, IP_PROTO_TCP, netif);
  NETIF_RESET_HINTS(netif);
#if WW_LWIP_WORKER_ENGINES
  /* Non-RST ACK emitters supply a mutable connected PCB. The const private
     signature additionally permits RST callers, which are excluded above. */
  ww_tcp_commit_advertisement(LWIP_CONST_CAST(struct tcp_pcb *, pcb), ww_advertised, err);
#endif]=])

    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[  if (wnd_inflation >= TCP_WND_UPDATE_THRESHOLD) {
    tcp_ack_now(pcb);
    tcp_output(pcb);
  }]=]
[=[  if (wnd_inflation >= TCP_WND_UPDATE_THRESHOLD) {
#if WW_LWIP_WORKER_ENGINES
    if (!ww_window_was_open || !wwLwipEngineDeferAck(pcb))
#endif
    {
      tcp_ack_now(pcb);
      tcp_output(pcb);
    }
  }]=])

    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[  LWIP_ASSERT("tcp_free: LISTEN", pcb->state != LISTEN);]=]
[=[  LWIP_ASSERT("tcp_free: LISTEN", pcb->state != LISTEN);
#if WW_LWIP_WORKER_ENGINES
  wwLwipEngineCancelAck(pcb);
#endif]=])

    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[  LWIP_ERROR("tcp_pcb_purge: invalid pcb", pcb != NULL, return);
]=]
[=[  LWIP_ERROR("tcp_pcb_purge: invalid pcb", pcb != NULL, return);
#if WW_LWIP_WORKER_ENGINES
  if (pcb->state != LISTEN) {
    wwLwipEngineCancelAck(pcb);
  }
#endif
]=])
endfunction()
