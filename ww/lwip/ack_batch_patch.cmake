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
[=[tcp_recved(struct tcp_pcb *pcb, u16_t len)
{
  WW_LWIP_ASSERT_PCB_OWNER(pcb);
  u32_t wnd_inflation;
  tcpwnd_size_t rcv_wnd;
#if WW_LWIP_WORKER_ENGINES
  u8_t ww_window_was_open;
#endif]=])

    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[  LWIP_ERROR("tcp_recved: invalid pcb", pcb != NULL, return);
]=]
[=[  LWIP_ERROR("tcp_recved: invalid pcb", pcb != NULL, return);
#if WW_LWIP_WORKER_ENGINES
  ww_window_was_open = RCV_WND_SCALE(pcb, pcb->rcv_ann_wnd) != 0;
#endif
]=])

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
