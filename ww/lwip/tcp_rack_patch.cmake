# Time-based loss detection for SACK peers (ww/lwip/tcp_rack.c, RFC 8985) in place of the
# three-duplicate-ACK rule, one congestion response per recovery episode, and timestamp
# undo of spurious recoveries. Applied after every other lwIP recipe, so the anchors below
# are the already-patched text. Connections without SACK keep lwIP's classic behavior.
function(ww_apply_lwip_tcp_rack_patch lwip_dir)
    # Per-pcb RACK state and the SACK blocks/timestamp echo of the ACK being processed.
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/tcp.h"
[=[  u8_t dupacks;]=]
[=[  u8_t dupacks;
#if WW_LWIP_TCP_RACK
  /* ww/lwip/tcp_rack.c */
  u32_t ww_rack_xmit_ms;       /* transmit time of the latest-sent delivered segment */
  u32_t ww_rack_end_seq;       /* its end sequence */
  u32_t ww_rack_rtt_ms;        /* its RTT sample */
  u32_t ww_rack_fack;          /* highest delivered end sequence */
  u32_t ww_rack_min_rtt_ms;
  u32_t ww_rack_srtt_ms;
  u32_t ww_rack_recover;       /* snd_nxt when the recovery episode started */
  u32_t ww_rack_retrans_stamp; /* first retransmission time of the episode */
  u32_t ww_rack_ts_ecr;        /* timestamp echo of the ACK being processed */
  u32_t ww_rack_sack[8];       /* SACK blocks of the ACK being processed (left, right) */
  tcpwnd_size_t ww_rack_undo_cwnd;
  tcpwnd_size_t ww_rack_undo_ssthresh;
  u32_t ww_rack_sacked_bytes; /* bytes of SACKed segments still above snd_una */
  u32_t ww_rack_lost_bytes;    /* bytes marked lost and not yet retransmitted */
  u32_t ww_rack_delivered;     /* RFC 6937 DeliveredData of the ACK being processed */
  u32_t ww_rack_prr_delivered; /* bytes delivered since recovery started */
  u32_t ww_rack_prr_out;       /* bytes sent since recovery started */
  u32_t ww_rack_recover_fs;    /* flight size when recovery started */
  u32_t ww_rack_progress_ms;   /* last delivery progress, probe timeout base */
  u16_t ww_rack_sacked_out;
  u8_t ww_rack_sack_count;
  u8_t ww_rack_state;
  u8_t ww_rack_reo_steps;
#endif]=])

    # Per-segment transmit time and scoreboard flags.
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/priv/tcp_priv.h"
[=[  struct tcp_hdr *tcphdr;  /* the TCP header */
};]=]
[=[  struct tcp_hdr *tcphdr;  /* the TCP header */
#if WW_LWIP_TCP_RACK
  u32_t ww_rack_xmit_ms;   /* last transmit time (sys_now), 0 = never sent */
  u8_t  ww_rack_flags;     /* WW_TCP_SEG_* */
#endif
};]=])

    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[#include "lwip/priv/tcp_priv.h"]=]
[=[#include "lwip/priv/tcp_priv.h"
#include "tcp_rack.h"
#if WW_LWIP_TCP_RACK
#define WW_TCP_RACK_CLASSIC_DUPACKS (!ww_rack)
#define WW_TCP_RACK_GROWS_CWND(pcb) (((pcb)->ww_rack_state & WW_TCP_RACK_RECOVERY) == 0)
#else
#define WW_TCP_RACK_CLASSIC_DUPACKS 1
#define WW_TCP_RACK_GROWS_CWND(pcb) 1
#endif]=])

    # Option state belongs to one segment; clear it before parsing.
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[  LWIP_ASSERT("tcp_parseopt: invalid pcb", pcb != NULL);
]=]
[=[  LWIP_ASSERT("tcp_parseopt: invalid pcb", pcb != NULL);
#if WW_LWIP_TCP_RACK
  pcb->ww_rack_sack_count = 0;
  pcb->ww_rack_state &= (u8_t)~WW_TCP_RACK_ECR_VALID;
#endif
]=])

    # Keep the timestamp echo instead of skipping it.
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[          /* Advance to next option (6 bytes already read) */
          ww_ctx_tcp_optidx += LWIP_TCP_OPT_LEN_TS - 6;]=]
[=[#if WW_LWIP_TCP_RACK
          {
            u32_t tsecr = (u32_t)tcp_get_next_optbyte() << 24;
            tsecr |= (u32_t)tcp_get_next_optbyte() << 16;
            tsecr |= (u32_t)tcp_get_next_optbyte() << 8;
            tsecr |= (u32_t)tcp_get_next_optbyte();
            if (ww_ctx_flags & TCP_ACK) {
              pcb->ww_rack_ts_ecr = tsecr;
              pcb->ww_rack_state |= WW_TCP_RACK_ECR_VALID;
            }
          }
#else
          /* Advance to next option (6 bytes already read) */
          ww_ctx_tcp_optidx += LWIP_TCP_OPT_LEN_TS - 6;
#endif]=])

    # Received SACK blocks. A malformed option stops parsing like the other options.
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[#endif /* LWIP_TCP_SACK_OUT */
        default:
          LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: other\n"));]=]
[=[#endif /* LWIP_TCP_SACK_OUT */
#if WW_LWIP_TCP_RACK
        case WW_TCP_OPT_SACK:
          data = tcp_get_next_optbyte();
          if (data < 10 || ((data - 2) % 8) != 0 || (ww_ctx_tcp_optidx - 2 + data) > ww_ctx_tcphdr_optlen) {
            LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: bad SACK length\n"));
            return;
          }
          {
            const u8_t blocks = (u8_t)((data - 2) / 8);
            u8_t block;
            for (block = 0; block < blocks; ++block) {
              u32_t edge[2];
              u8_t side;
              for (side = 0; side < 2; ++side) {
                edge[side] = (u32_t)tcp_get_next_optbyte() << 24;
                edge[side] |= (u32_t)tcp_get_next_optbyte() << 16;
                edge[side] |= (u32_t)tcp_get_next_optbyte() << 8;
                edge[side] |= (u32_t)tcp_get_next_optbyte();
              }
              if (pcb->ww_rack_sack_count < 4) {
                pcb->ww_rack_sack[2 * pcb->ww_rack_sack_count] = edge[0];
                pcb->ww_rack_sack[2 * pcb->ww_rack_sack_count + 1] = edge[1];
                ++pcb->ww_rack_sack_count;
              }
            }
          }
          break;
#endif /* WW_LWIP_TCP_RACK */
        default:
          LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: other\n"));]=])

    # Scoreboard and RACK delivery state are updated before lwIP frees acknowledged segments.
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[    /* (From Stevens TCP/IP Illustrated Vol II, p970.) Its only a]=]
[=[#if WW_LWIP_TCP_RACK
    const int ww_rack = wwTcpRackActive(pcb);
    wwTcpRackOnAck(pcb, ww_ctx_ackno);
#endif
    /* (From Stevens TCP/IP Illustrated Vol II, p970.) Its only a]=])

    # With RACK, duplicate ACKs neither inflate cwnd nor trigger retransmission.
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[              if (pcb->dupacks > 3) {
                /* Inflate the congestion window */
                TCP_WND_INC(pcb->cwnd, pcb->mss);
              }
              if (pcb->dupacks >= 3) {]=]
[=[              if (pcb->dupacks > 3 && WW_TCP_RACK_CLASSIC_DUPACKS) {
                /* Inflate the congestion window */
                TCP_WND_INC(pcb->cwnd, pcb->mss);
              }
              if (pcb->dupacks >= 3 && WW_TCP_RACK_CLASSIC_DUPACKS) {]=])

    # No window growth from partial ACKs inside a recovery episode.
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[      if (pcb->state >= ESTABLISHED) {
        if (pcb->cwnd < pcb->ssthresh) {]=]
[=[      if (pcb->state >= ESTABLISHED && WW_TCP_RACK_GROWS_CWND(pcb)) {
        if (pcb->cwnd < pcb->ssthresh) {]=])

    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[    LWIP_DEBUGF(TCP_RTO_DEBUG, ("tcp_receive: pcb->rttest %"U32_F" rtseq %"U32_F" ww_ctx_ackno %"U32_F"\n",]=]
[=[#if WW_LWIP_TCP_RACK
    if (ww_rack) {
      wwTcpRackAfterAck(pcb);
    }
#endif
    LWIP_DEBUGF(TCP_RTO_DEBUG, ("tcp_receive: pcb->rttest %"U32_F" rtseq %"U32_F" ww_ctx_ackno %"U32_F"\n",]=])

    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[#include "lwip/priv/tcp_priv.h"]=]
[=[#include "lwip/priv/tcp_priv.h"
#include "tcp_rack.h"]=])

    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[  seg->flags = optflags;
  seg->next = NULL;]=]
[=[  seg->flags = optflags;
  seg->next = NULL;
#if WW_LWIP_TCP_RACK
  seg->ww_rack_xmit_ms = 0;
  seg->ww_rack_flags = 0;
#endif]=])

    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[    LWIP_DEBUGF(TCP_RTO_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("tcp_output_segment: segment busy\n"));
    return ERR_OK;
  }
]=]
[=[    LWIP_DEBUGF(TCP_RTO_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("tcp_output_segment: segment busy\n"));
    return ERR_OK;
  }
#if WW_LWIP_TCP_RACK
  wwTcpRackOnTransmit(pcb, seg);
#endif
]=])

    # Segments RACK marked lost are retransmitted even beyond the cwnd edge measured from
    # snd_una, and with SACK state cwnd limits the pipe (RFC 6675) rather than snd_nxt - snd_una,
    # so SACKed data keeps the ACK clock running through recovery.
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[  if (lwip_ntohl(seg->tcphdr->seqno) - pcb->lastack + seg->len > wnd) {]=]
[=[  if (!WW_TCP_RACK_SENDABLE(pcb, seg, wnd)) {]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[  while (seg != NULL &&
         lwip_ntohl(seg->tcphdr->seqno) - pcb->lastack + seg->len <= wnd) {]=]
[=[  while (seg != NULL && WW_TCP_RACK_SENDABLE(pcb, seg, wnd)) {]=])

    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[  LWIP_ASSERT("tcp_rexmit_rto_prepare: invalid pcb", pcb != NULL);
]=]
[=[  LWIP_ASSERT("tcp_rexmit_rto_prepare: invalid pcb", pcb != NULL);
#if WW_LWIP_TCP_RACK
  wwTcpRackOnRto(pcb);
#endif
]=])
    # Reordering-timer fallback when ACKs stop (tcp_fasttmr granularity).
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[#include "lwip/priv/tcp_priv.h"]=]
[=[#include "lwip/priv/tcp_priv.h"
#include "tcp_rack.h"]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[      pcb->last_timer = ww_ctx_tcp_timer_ctr;
      /* send delayed ACKs */]=]
[=[      pcb->last_timer = ww_ctx_tcp_timer_ctr;
#if WW_LWIP_TCP_RACK
      if (wwTcpRackOnTimer(pcb)) {
        tcp_output(pcb);
      }
#endif
      /* send delayed ACKs */]=])
endfunction()
