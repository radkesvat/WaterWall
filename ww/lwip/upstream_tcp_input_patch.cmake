# Apply the upstream tcp_in.c fixes to the pristine pinned source before WaterWall's overlays.
function(ww_apply_lwip_upstream_tcp_input_patch lwip_dir)
    set(tcp_in "${lwip_dir}/src/core/tcp_in.c")

    # 3d896ba0a37ff3ce73270ca5e230707fe47f60e3: bound the option-byte reader.
    ww_lwip_replace_once("${tcp_in}"
[=[  u16_t optidx = tcp_optidx++;
  if ((tcphdr_opt2 == NULL) || (optidx < tcphdr_opt1len)) {]=]
[=[  u16_t optidx = tcp_optidx++;
  if (optidx >= tcphdr_optlen) {
    /* Return 0 for any excess reads (like length fields) */
    return LWIP_TCP_OPT_EOL;
  }
  if ((tcphdr_opt2 == NULL) || (optidx < tcphdr_opt1len)) {]=])

    # 6a3a9442077b05e961e6ab42e599255d0c98af8d: validate sequence numbers in SYN_RCVD.
    ww_lwip_replace_once("${tcp_in}"
[=[      } else if (flags & TCP_ACK) {
        /* expected ACK number? */]=]
[=[      } else if (flags & TCP_ACK) {
        /* Check sequence-number acceptability before completing the
         * handshake or notifying the application. */
        if (pcb->rcv_wnd == 0) {
          /* Window cannot be 0 here, just drop the packet. */
          LWIP_DEBUGF(TCP_DEBUG, ("TCP has zero rcv_wnd in SYN_RCVD.\n"));
          return ERR_OK;
        } else {
          u32_t wnd_end = pcb->rcv_nxt + pcb->rcv_wnd - 1;
          u32_t seq_end = seqno + tcplen - 1;

          if (tcplen == 0) {
            if (!TCP_SEQ_BETWEEN(seqno, pcb->rcv_nxt, wnd_end)) {
              tcp_ack_now(pcb);
              return ERR_OK;
            }
          } else if (!TCP_SEQ_BETWEEN(seqno, pcb->rcv_nxt, wnd_end) &&
                     !TCP_SEQ_BETWEEN(seq_end, pcb->rcv_nxt, wnd_end)) {
            tcp_ack_now(pcb);
            return ERR_OK;
          }
        }
        /* expected ACK number? */]=])

    # 3b94c1abb752ae416be47452b9c8c4a62a7eba22: trim out-of-sequence segments before enqueueing.
    ww_lwip_replace_once("${tcp_in}"
[=[#if TCP_QUEUE_OOSEQ
        /* We queue the segment on the ->ooseq queue. */
        if (pcb->ooseq == NULL) {]=]
[=[#if TCP_QUEUE_OOSEQ
        /* The segment start was checked against the receive window, but its
         * right edge may still extend beyond it. Trim before queuing so that
         * dequeuing the segment cannot consume more than the remaining window. */
         right_wnd_edge = pcb->rcv_nxt + pcb->rcv_wnd - seqno;
         if ((TCPH_FLAGS(inseg.tcphdr) & TCP_FIN) && (inseg.len >= right_wnd_edge)) {
           /* FIN consumes one sequence number after the payload. */
           TCPH_FLAGS_SET(inseg.tcphdr, TCPH_FLAGS(inseg.tcphdr) & ~(unsigned int)TCP_FIN);
         }
         if (inseg.len > right_wnd_edge) {
           inseg.len = (u16_t)right_wnd_edge;
           pbuf_realloc(inseg.p, inseg.len);
         }
         tcplen = TCP_TCPLEN(&inseg);

         /* We queue the segment on the ->ooseq queue. */
        if (pcb->ooseq == NULL) {]=])

    # 777e6d40d510a3de4357a268532f6b5bcc039037: keep a queued FIN until the receive window admits it.
    ww_lwip_replace_once("${tcp_in}"
[=[              if ((TCPH_FLAGS(next->tcphdr) & TCP_FIN) != 0 &&
                  (TCPH_FLAGS(inseg.tcphdr) & TCP_SYN) == 0) {
                TCPH_SET_FLAG(inseg.tcphdr, TCP_FIN);]=]
[=[              if ((TCPH_FLAGS(next->tcphdr) & TCP_FIN) != 0 &&
                  (TCPH_FLAGS(inseg.tcphdr) & TCP_SYN) == 0) {
                /* Copying the FIN consumes one more sequence number. If inseg
                   was already trimmed to fill the receive window, that extra
                   byte would push tcplen past rcv_wnd and underflow the window
                   update below. Leave the FIN segment on ooseq to be processed
                   once the window has advanced. */
                if (tcplen >= pcb->rcv_wnd) {
                  break;
                }
                TCPH_SET_FLAG(inseg.tcphdr, TCP_FIN);]=])
endfunction()
