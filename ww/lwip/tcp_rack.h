#pragma once

/*
 * Time-based TCP loss detection for SACK peers (RACK, RFC 8985) with one congestion
 * response per recovery episode (RFC 6675 recovery point) and timestamp-based undo of
 * spurious recoveries (Eifel detection, RFC 3522).
 *
 * The lwIP sender otherwise treats three duplicate ACKs as loss, retransmits only the
 * head segment and halves cwnd again for every further hole. On reordering paths that
 * turns delivered-but-late segments into repeated window collapses. RACK marks a segment
 * lost only when a segment sent after it has been delivered and a reordering window has
 * elapsed, so reordering shorter than that window costs nothing.
 *
 * Hooks are inserted by tcp_rack_patch.cmake. Every hook is a no-op unless the
 * connection negotiated SACK; peers without SACK keep lwIP's classic fast retransmit.
 */

#include "lwip/opt.h"

#if LWIP_TCP && WW_LWIP_TCP_RACK

#include "lwip/arch.h"

struct tcp_pcb;
struct tcp_seg;

/* SACK option kind (RFC 2018). lwIP only names SACK-permitted. */
#define WW_TCP_OPT_SACK 5

/* tcp_seg.ww_rack_flags */
#define WW_TCP_SEG_SACKED  0x01U /* fully covered by a received SACK block */
#define WW_TCP_SEG_LOST    0x02U /* marked lost, waiting for retransmission */
#define WW_TCP_SEG_RETRANS 0x04U /* transmitted more than once */

/* tcp_pcb.ww_rack_state */
#define WW_TCP_RACK_SAMPLED    0x01U /* ww_rack_xmit_ms/end_seq/rtt_ms hold a delivery sample */
#define WW_TCP_RACK_REORDERED  0x02U /* reordering observed on this connection */
#define WW_TCP_RACK_RECOVERY   0x04U /* inside a loss-recovery episode */
#define WW_TCP_RACK_STAMPED    0x08U /* ww_rack_retrans_stamp is valid for this episode */
#define WW_TCP_RACK_ECR_VALID  0x10U /* the ACK being processed carried a timestamp echo */
#define WW_TCP_RACK_FACK_VALID 0x20U /* ww_rack_fack is valid */
#define WW_TCP_RACK_PROBED     0x40U /* a tail loss probe is outstanding */

/* Upper bound of the reordering-window multiplier after repeated spurious recoveries. */
#define WW_TCP_RACK_REO_STEPS_MAX 16U

/* Returns non-zero when RACK replaces duplicate-ACK loss detection for this pcb. */
int wwTcpRackActive(const struct tcp_pcb *pcb);

/* Before lwIP consumes an ACK: SACK scoreboard, RACK delivery state, spurious-recovery undo. */
void wwTcpRackOnAck(struct tcp_pcb *pcb, u32_t ackno);

/* After lwIP consumed an ACK: recovery exit, loss marking and queueing of lost segments. */
void wwTcpRackAfterAck(struct tcp_pcb *pcb);

/* tcp_output_segment(): stamp transmit time and retransmission state. */
void wwTcpRackOnTransmit(struct tcp_pcb *pcb, struct tcp_seg *seg);

/* Retransmission timeout: every outstanding segment is requeued, the scoreboard restarts. */
void wwTcpRackOnRto(struct tcp_pcb *pcb);

/* tcp_fasttmr(): loss detection when no ACK arrives. Returns non-zero when segments were
   queued for retransmission and tcp_output() should run. */
int wwTcpRackOnTimer(struct tcp_pcb *pcb);

/* tcp_output() window test: lost segments always, otherwise SACK-aware pipe against cwnd
   and the sequence span against the peer window. Equals lwIP's test without SACK state. */
int wwTcpRackSendable(const struct tcp_pcb *pcb, const struct tcp_seg *seg, u32_t wnd);

#define WW_TCP_RACK_SENDABLE(pcb, seg, wnd) wwTcpRackSendable((pcb), (seg), (wnd))

#else

#define WW_TCP_RACK_SENDABLE(pcb, seg, wnd) (lwip_ntohl((seg)->tcphdr->seqno) - (pcb)->lastack + (seg)->len <= (wnd))

#endif
