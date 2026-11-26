#include "tcp_rack.h"

#if LWIP_TCP && WW_LWIP_TCP_RACK

#include "lwip/def.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/stats.h"
#include "lwip/sys.h"

#include <stdint.h>

/* RFC 8985 keeps the classic three-duplicate threshold only for the case where no
   reordering has been seen yet and loss evidence already exceeds it. */
#define WW_TCP_RACK_DUPTHRESH 3U

static inline s32_t rackTimeDiff(u32_t a, u32_t b)
{
    return (s32_t) (a - b);
}

static inline u32_t rackSegEnd(const struct tcp_seg *seg)
{
    return lwip_ntohl(seg->tcphdr->seqno) + TCP_TCPLEN(seg);
}

static inline int rackHas(const struct tcp_pcb *pcb, u8_t bit)
{
    return (pcb->ww_rack_state & bit) != 0;
}

int wwTcpRackActive(const struct tcp_pcb *pcb)
{
    return (pcb->flags & TF_SACK) != 0;
}

/* RFC 8985 6.2 steps 1-3 for one newly delivered (cumulatively ACKed or SACKed) segment. */
static void rackOnDelivered(struct tcp_pcb *pcb, const struct tcp_seg *seg, u32_t now, u32_t fack_before,
                            int cumulative)
{
    const u32_t end = rackSegEnd(seg);

    /* A never-retransmitted segment delivered below the highest delivered sequence was
       reordered, not lost. */
    if (rackHas(pcb, WW_TCP_RACK_FACK_VALID))
    {
        if (! (seg->ww_rack_flags & WW_TCP_SEG_RETRANS) && TCP_SEQ_LT(end, fack_before))
        {
            pcb->ww_rack_state |= WW_TCP_RACK_REORDERED;
        }
        if (TCP_SEQ_GT(end, pcb->ww_rack_fack))
        {
            pcb->ww_rack_fack = end;
        }
    }
    else
    {
        pcb->ww_rack_fack = end;
        pcb->ww_rack_state |= WW_TCP_RACK_FACK_VALID;
    }

    const u32_t rtt = now - seg->ww_rack_xmit_ms;
    if (seg->ww_rack_flags & WW_TCP_SEG_RETRANS)
    {
        /* Ambiguous sample. The timestamp echo identifies the segment that advanced the
           receiver's left edge (RFC 7323), so it only disambiguates a cumulative ACK: an echo
           older than the retransmission acknowledges the original. For a SACKed segment the
           echo belongs to a different segment; like Linux, rely on the minimum-RTT test:
           an RTT below it cannot belong to the retransmission. */
        if (cumulative && rackHas(pcb, WW_TCP_RACK_ECR_VALID) &&
            rackTimeDiff(pcb->ww_rack_ts_ecr, seg->ww_rack_xmit_ms) < 0)
        {
            return;
        }
        if (pcb->ww_rack_min_rtt_ms != 0 && rtt < pcb->ww_rack_min_rtt_ms)
        {
            return;
        }
    }

    const u32_t sample = rtt != 0 ? rtt : 1;
    if (pcb->ww_rack_min_rtt_ms == 0 || sample < pcb->ww_rack_min_rtt_ms)
    {
        pcb->ww_rack_min_rtt_ms = sample;
    }
    pcb->ww_rack_srtt_ms = pcb->ww_rack_srtt_ms == 0 ? sample : (7U * pcb->ww_rack_srtt_ms + sample) / 8U;

    if (! rackHas(pcb, WW_TCP_RACK_SAMPLED) || rackTimeDiff(seg->ww_rack_xmit_ms, pcb->ww_rack_xmit_ms) > 0 ||
        (seg->ww_rack_xmit_ms == pcb->ww_rack_xmit_ms && TCP_SEQ_GT(end, pcb->ww_rack_end_seq)))
    {
        pcb->ww_rack_xmit_ms = seg->ww_rack_xmit_ms;
        pcb->ww_rack_end_seq = end;
        pcb->ww_rack_rtt_ms  = sample;
        pcb->ww_rack_state |= WW_TCP_RACK_SAMPLED;
    }
}

/* RFC 6675 pipe: outstanding bytes minus those SACKed or marked lost and not yet resent. */
static u32_t rackPipe(const struct tcp_pcb *pcb)
{
    const u32_t flight = pcb->snd_nxt - pcb->lastack;
    const u32_t gone   = pcb->ww_rack_sacked_bytes + pcb->ww_rack_lost_bytes;
    return flight - LWIP_MIN(flight, gone);
}

/* RFC 3522 / RFC 8985 9.3: the recovery was spurious, restore the pre-recovery window and
   widen the reordering window for the rest of the connection. */
static void rackUndo(struct tcp_pcb *pcb)
{
    if (pcb->cwnd < pcb->ww_rack_undo_cwnd)
    {
        pcb->cwnd = pcb->ww_rack_undo_cwnd;
    }
    if (pcb->ssthresh < pcb->ww_rack_undo_ssthresh)
    {
        pcb->ssthresh = pcb->ww_rack_undo_ssthresh;
    }
    pcb->ww_rack_state &= (u8_t) ~(WW_TCP_RACK_RECOVERY | WW_TCP_RACK_STAMPED);
    pcb->ww_rack_state |= WW_TCP_RACK_REORDERED;
    if (pcb->ww_rack_reo_steps < WW_TCP_RACK_REO_STEPS_MAX)
    {
        ++pcb->ww_rack_reo_steps;
    }
    for (struct tcp_seg *seg = pcb->unacked; seg != NULL; seg = seg->next)
    {
        seg->ww_rack_flags &= (u8_t) ~WW_TCP_SEG_LOST;
    }
    /* Segments already queued for retransmission still go out; only they remain counted. */
    pcb->ww_rack_lost_bytes = 0;
    for (struct tcp_seg *seg = pcb->unsent; seg != NULL; seg = seg->next)
    {
        if (seg->ww_rack_flags & WW_TCP_SEG_LOST)
        {
            pcb->ww_rack_lost_bytes += TCP_TCPLEN(seg);
        }
    }
}

void wwTcpRackOnAck(struct tcp_pcb *pcb, u32_t ackno)
{
    if (! wwTcpRackActive(pcb))
    {
        return;
    }
    const u32_t now         = sys_now();
    const u32_t fack_before = pcb->ww_rack_fack;
    /* RFC 6937 DeliveredData: newly cumulatively ACKed plus newly SACKed bytes, without
       counting twice what was already SACKed. */
    u32_t delivered = TCP_SEQ_GT(ackno, pcb->lastack) ? ackno - pcb->lastack : 0;
    u32_t resacked  = 0;

    if (rackHas(pcb, WW_TCP_RACK_RECOVERY) && rackHas(pcb, WW_TCP_RACK_STAMPED) &&
        rackHas(pcb, WW_TCP_RACK_ECR_VALID) && TCP_SEQ_GT(ackno, pcb->lastack) &&
        rackTimeDiff(pcb->ww_rack_ts_ecr, pcb->ww_rack_retrans_stamp) < 0)
    {
        /* Newly acknowledged data was sent before the first retransmission of this episode
           and still arrived: the original was late, not lost. */
        rackUndo(pcb);
    }

    struct tcp_seg *seg = pcb->unacked;
    for (; seg != NULL && TCP_SEQ_LEQ(rackSegEnd(seg), ackno); seg = seg->next)
    {
        if (seg->ww_rack_flags & WW_TCP_SEG_SACKED)
        {
            if (pcb->ww_rack_sacked_out != 0)
            {
                --pcb->ww_rack_sacked_out;
            }
            pcb->ww_rack_sacked_bytes -= LWIP_MIN(pcb->ww_rack_sacked_bytes, (u32_t) TCP_TCPLEN(seg));
            resacked += TCP_TCPLEN(seg);
            continue;
        }
        if (seg->ww_rack_flags & WW_TCP_SEG_LOST)
        {
            pcb->ww_rack_lost_bytes -= LWIP_MIN(pcb->ww_rack_lost_bytes, (u32_t) TCP_TCPLEN(seg));
        }
        if (seg->ww_rack_xmit_ms != 0)
        {
            rackOnDelivered(pcb, seg, now, fack_before, 1);
        }
    }

    /* Lost segments waiting in unsent can be covered by this ACK (the original was late). */
    for (struct tcp_seg *u = pcb->unsent; u != NULL && TCP_SEQ_LEQ(rackSegEnd(u), ackno); u = u->next)
    {
        if (u->ww_rack_flags & WW_TCP_SEG_LOST)
        {
            pcb->ww_rack_lost_bytes -= LWIP_MIN(pcb->ww_rack_lost_bytes, (u32_t) TCP_TCPLEN(u));
        }
    }

    for (u8_t i = 0; i < pcb->ww_rack_sack_count; ++i)
    {
        const u32_t left  = pcb->ww_rack_sack[2U * i];
        const u32_t right = pcb->ww_rack_sack[2U * i + 1U];
        if (! TCP_SEQ_GT(right, left) || ! TCP_SEQ_GT(right, ackno) || TCP_SEQ_GT(right, pcb->snd_nxt))
        {
            continue; /* empty, already cumulatively acknowledged, or beyond what was sent */
        }
        for (struct tcp_seg *s = seg; s != NULL; s = s->next)
        {
            const u32_t start = lwip_ntohl(s->tcphdr->seqno);
            if (TCP_SEQ_GEQ(start, right))
            {
                break;
            }
            if ((s->ww_rack_flags & WW_TCP_SEG_SACKED) || TCP_SEQ_LT(start, left) || TCP_SEQ_GT(rackSegEnd(s), right))
            {
                continue;
            }
            if (s->ww_rack_flags & WW_TCP_SEG_LOST)
            {
                pcb->ww_rack_lost_bytes -= LWIP_MIN(pcb->ww_rack_lost_bytes, (u32_t) TCP_TCPLEN(s));
            }
            s->ww_rack_flags |= WW_TCP_SEG_SACKED;
            s->ww_rack_flags &= (u8_t) ~WW_TCP_SEG_LOST;
            delivered += TCP_TCPLEN(s);
            if (pcb->ww_rack_sacked_out < 0xffffU)
            {
                ++pcb->ww_rack_sacked_out;
            }
            pcb->ww_rack_sacked_bytes += TCP_TCPLEN(s);
            if (s->ww_rack_xmit_ms != 0)
            {
                rackOnDelivered(pcb, s, now, fack_before, 0);
            }
        }
    }
    pcb->ww_rack_delivered = delivered - LWIP_MIN(delivered, resacked);
    if (pcb->ww_rack_delivered != 0)
    {
        pcb->ww_rack_progress_ms = now;
        pcb->ww_rack_state &= (u8_t) ~WW_TCP_RACK_PROBED;
    }
}

/* RFC 8985 6.2 step 4. */
static u32_t rackReorderWindow(const struct tcp_pcb *pcb);
static u32_t rackReorderWindow(const struct tcp_pcb *pcb)
{
    if (! rackHas(pcb, WW_TCP_RACK_REORDERED) &&
        (rackHas(pcb, WW_TCP_RACK_RECOVERY) || pcb->ww_rack_sacked_out >= WW_TCP_RACK_DUPTHRESH))
    {
        return 0;
    }
    const u32_t steps  = pcb->ww_rack_reo_steps != 0 ? pcb->ww_rack_reo_steps : 1U;
    const u32_t window = (pcb->ww_rack_min_rtt_ms / 4U) * steps;
    return LWIP_MIN(window, pcb->ww_rack_srtt_ms);
}

/* Moves lost segments from unacked to the sorted unsent queue. tcp_output() sends them
   ahead of the window check (WW_TCP_RACK_SEG_FORCED) and onTransmit() clears the mark. */
static int rackQueueLost(struct tcp_pcb *pcb)
{
    int              moved = 0;
    struct tcp_seg **link  = &pcb->unacked;
    while (*link != NULL)
    {
        struct tcp_seg *seg = *link;
        if (! (seg->ww_rack_flags & WW_TCP_SEG_LOST) || seg->p->ref != 1)
        {
            link = &seg->next;
            continue;
        }
        *link = seg->next;

        struct tcp_seg **at = &pcb->unsent;
        while (*at != NULL && TCP_SEQ_LT(lwip_ntohl((*at)->tcphdr->seqno), lwip_ntohl(seg->tcphdr->seqno)))
        {
            at = &(*at)->next;
        }
        seg->next = *at;
        *at       = seg;
#if TCP_OVERSIZE
        if (seg->next == NULL)
        {
            pcb->unsent_oversize = 0;
        }
#endif
        /* pcb->nrtx is left alone: it counts retransmission timeouts and lwIP aborts the
           connection at TCP_MAXRTX, which one deep hole would otherwise reach. */
        MIB2_STATS_INC(mib2.tcpretranssegs);
        moved = 1;
    }
    if (moved)
    {
#if WW_LWIP_WORKER_ENGINES
        struct tcp_seg *tail = pcb->unacked;
        while (tail != NULL && tail->next != NULL)
        {
            tail = tail->next;
        }
        pcb->ww_unacked_tail = tail;
#endif
        pcb->rttest = 0; /* Karn: no RTT sample across a retransmission */
        pcb->rtime  = 0;
    }
    return moved;
}

static int rackDetectLoss(struct tcp_pcb *pcb)
{

    /* RFC 8985 6.2 step 5: a segment sent before the most recently delivered one is lost
       once its RTT plus the reordering window has elapsed. Segments at or beyond the RACK
       end sequence were first sent later and cannot qualify. */
    const u32_t now     = sys_now();
    const u32_t reo_wnd = rackReorderWindow(pcb);
    int         lost    = 0;
    for (struct tcp_seg *seg = pcb->unacked; seg != NULL; seg = seg->next)
    {
        const u32_t start = lwip_ntohl(seg->tcphdr->seqno);
        if (TCP_SEQ_GEQ(start, pcb->ww_rack_end_seq) && ! (seg->ww_rack_flags & WW_TCP_SEG_RETRANS))
        {
            break;
        }
        if (seg->ww_rack_flags & (WW_TCP_SEG_SACKED | WW_TCP_SEG_LOST))
        {
            lost |= (seg->ww_rack_flags & WW_TCP_SEG_LOST) != 0;
            continue;
        }
        const s32_t sent_before = rackTimeDiff(pcb->ww_rack_xmit_ms, seg->ww_rack_xmit_ms);
        if (sent_before < 0 || (sent_before == 0 && ! TCP_SEQ_GT(pcb->ww_rack_end_seq, rackSegEnd(seg))))
        {
            continue;
        }
        if (rackTimeDiff(now, seg->ww_rack_xmit_ms + pcb->ww_rack_rtt_ms + reo_wnd) >= 0)
        {
            seg->ww_rack_flags |= WW_TCP_SEG_LOST;
            pcb->ww_rack_lost_bytes += TCP_TCPLEN(seg);
            lost = 1;
        }
    }
    if (! lost)
    {
        return 0;
    }

    if (! rackHas(pcb, WW_TCP_RACK_RECOVERY))
    {
        /* One congestion response per episode, ending when everything outstanding at its
           start is acknowledged (RFC 6675 RecoveryPoint). */
        pcb->ww_rack_undo_cwnd     = pcb->cwnd;
        pcb->ww_rack_undo_ssthresh = pcb->ssthresh;
        pcb->ww_rack_recover       = pcb->snd_nxt;
        pcb->ssthresh              = LWIP_MIN(pcb->cwnd, pcb->snd_wnd) / 2;
        if (pcb->ssthresh < 2U * pcb->mss)
        {
            pcb->ssthresh = 2U * pcb->mss;
        }
        pcb->ww_rack_recover_fs    = LWIP_MAX(pcb->snd_nxt - pcb->lastack, 1U);
        pcb->ww_rack_prr_delivered = 0;
        pcb->ww_rack_prr_out       = 0;
        pcb->ww_rack_state |= WW_TCP_RACK_RECOVERY;
        pcb->ww_rack_state &= (u8_t) ~WW_TCP_RACK_STAMPED;
    }
    return rackQueueLost(pcb);
}

/* RFC 2018 8 / RFC 6675 5.1: a receiver may discard data it already SACKed (lwIP's own
   out-of-order trim does). When the cumulative ACK stops at a segment believed SACKed, the
   scoreboard no longer reflects the receiver: forget all SACK marks and resend that segment
   instead of waiting for the retransmission timeout. */
static void rackCheckReneging(struct tcp_pcb *pcb)
{
    struct tcp_seg *head = pcb->unacked;
    if (head == NULL || ! (head->ww_rack_flags & WW_TCP_SEG_SACKED) || lwip_ntohl(head->tcphdr->seqno) != pcb->lastack)
    {
        return;
    }
    for (struct tcp_seg *seg = head; seg != NULL; seg = seg->next)
    {
        seg->ww_rack_flags &= (u8_t) ~WW_TCP_SEG_SACKED;
    }
    pcb->ww_rack_sacked_out   = 0;
    pcb->ww_rack_sacked_bytes = 0;
    if (! (head->ww_rack_flags & WW_TCP_SEG_LOST))
    {
        head->ww_rack_flags |= WW_TCP_SEG_LOST;
        pcb->ww_rack_lost_bytes += TCP_TCPLEN(head);
    }
}

void wwTcpRackAfterAck(struct tcp_pcb *pcb)
{
    if (! wwTcpRackActive(pcb))
    {
        return;
    }
    if (rackHas(pcb, WW_TCP_RACK_RECOVERY) && TCP_SEQ_GEQ(pcb->lastack, pcb->ww_rack_recover))
    {
        pcb->ww_rack_state &= (u8_t) ~(WW_TCP_RACK_RECOVERY | WW_TCP_RACK_STAMPED);
        pcb->cwnd = pcb->ssthresh;
    }
    rackCheckReneging(pcb);
    if (rackHas(pcb, WW_TCP_RACK_SAMPLED))
    {
        (void) rackDetectLoss(pcb);
    }
    if (rackHas(pcb, WW_TCP_RACK_RECOVERY))
    {
        /* RFC 6937 Proportional Rate Reduction: keep sending in proportion to delivery so the
           ACK clock survives recovery and RACK can still detect a lost retransmission. */
        pcb->ww_rack_prr_delivered += pcb->ww_rack_delivered;
        const u32_t pipe = rackPipe(pcb);
        s32_t       sndcnt;
        if (pipe > pcb->ssthresh)
        {
            const uint64_t target =
                ((uint64_t) pcb->ww_rack_prr_delivered * pcb->ssthresh + pcb->ww_rack_recover_fs - 1U) /
                pcb->ww_rack_recover_fs;
            sndcnt = (s32_t) ((int64_t) target - (int64_t) pcb->ww_rack_prr_out);
        }
        else
        {
            const int64_t owed  = (int64_t) pcb->ww_rack_prr_delivered - (int64_t) pcb->ww_rack_prr_out;
            const int64_t limit = LWIP_MAX(owed, (int64_t) pcb->ww_rack_delivered) + pcb->mss;
            sndcnt              = (s32_t) LWIP_MIN((int64_t) (pcb->ssthresh - pipe), limit);
        }
        pcb->cwnd = (tcpwnd_size_t) (pipe + (u32_t) LWIP_MAX(sndcnt, 0));
    }
    pcb->ww_rack_delivered = 0;
}

/* RFC 8985 7: when a whole tail is lost no later segment is delivered and RACK has nothing to
   compare against. After a probe timeout of two smoothed RTTs without delivery progress,
   resend the highest outstanding segment once; the ACK it elicits (with SACK) lets RACK repair
   the tail instead of waiting for the retransmission timeout. */
static int rackTailLossProbe(struct tcp_pcb *pcb)
{
    if (rackHas(pcb, WW_TCP_RACK_PROBED) || pcb->ww_rack_srtt_ms == 0 || pcb->nrtx != 0)
    {
        return 0;
    }
    const u32_t pto = LWIP_MAX(2U * pcb->ww_rack_srtt_ms, 10U);
    if (rackTimeDiff(sys_now(), pcb->ww_rack_progress_ms + pto) < 0)
    {
        return 0;
    }
    struct tcp_seg *last = pcb->unacked;
    while (last->next != NULL)
    {
        last = last->next;
    }
    if (last->ww_rack_flags & (WW_TCP_SEG_SACKED | WW_TCP_SEG_LOST))
    {
        return 0;
    }
    pcb->ww_rack_state |= WW_TCP_RACK_PROBED;
    last->ww_rack_flags |= WW_TCP_SEG_LOST;
    pcb->ww_rack_lost_bytes += TCP_TCPLEN(last);
    return rackQueueLost(pcb);
}

int wwTcpRackOnTimer(struct tcp_pcb *pcb)
{
    /* RFC 8985 6.3 reordering timer, at tcp_fasttmr granularity: when ACKs stop, a hole whose
       reordering window expired after the last ACK is still detected without waiting for the
       retransmission timeout. */
    if (pcb->unacked != NULL || pcb->unsent != NULL)
    {
    }
    if (! wwTcpRackActive(pcb) || ! rackHas(pcb, WW_TCP_RACK_SAMPLED) || pcb->unacked == NULL)
    {
        return 0;
    }
    rackCheckReneging(pcb);
    if ((pcb->ww_rack_sacked_out != 0 || pcb->ww_rack_lost_bytes != 0 || rackHas(pcb, WW_TCP_RACK_RECOVERY)) &&
        rackDetectLoss(pcb))
    {
        return 1;
    }
    return rackTailLossProbe(pcb);
}

int wwTcpRackSendable(const struct tcp_pcb *pcb, const struct tcp_seg *seg, u32_t wnd)
{
    const u32_t span = lwip_ntohl(seg->tcphdr->seqno) - pcb->lastack + seg->len;
    if (seg->ww_rack_flags & WW_TCP_SEG_LOST)
    {
        return 1; /* retransmission of a segment RACK declared lost */
    }
    if (! wwTcpRackActive(pcb) ||
        (pcb->ww_rack_sacked_bytes == 0 && pcb->ww_rack_lost_bytes == 0 && ! rackHas(pcb, WW_TCP_RACK_RECOVERY)))
    {
        return span <= wnd;
    }
    /* RFC 6675 pipe against cwnd; the peer's window stays sequence-based. */
    if (span > pcb->snd_wnd)
    {
        return 0;
    }
    return rackPipe(pcb) + seg->len <= pcb->cwnd;
}

void wwTcpRackOnTransmit(struct tcp_pcb *pcb, struct tcp_seg *seg)
{
    const u32_t now = sys_now();
    if (pcb->unacked == NULL && TCP_TCPLEN(seg) != 0)
    {
        pcb->ww_rack_progress_ms = now; /* the probe timeout counts from the first byte in flight */
        pcb->ww_rack_state &= (u8_t) ~WW_TCP_RACK_PROBED;
    }
    /* A stamped segment was sent before. Sequence position is not a substitute: an RTO
       rewinds snd_nxt below segments that are then resent. */
    if (TCP_TCPLEN(seg) != 0 && seg->ww_rack_xmit_ms != 0)
    {
        seg->ww_rack_flags |= WW_TCP_SEG_RETRANS;
        if (rackHas(pcb, WW_TCP_RACK_RECOVERY) && ! rackHas(pcb, WW_TCP_RACK_STAMPED))
        {
            pcb->ww_rack_retrans_stamp = now;
            pcb->ww_rack_state |= WW_TCP_RACK_STAMPED;
        }
    }
    if (seg->ww_rack_flags & WW_TCP_SEG_LOST)
    {
        pcb->ww_rack_lost_bytes -= LWIP_MIN(pcb->ww_rack_lost_bytes, (u32_t) TCP_TCPLEN(seg));
    }
    if (rackHas(pcb, WW_TCP_RACK_RECOVERY))
    {
        pcb->ww_rack_prr_out += TCP_TCPLEN(seg);
    }
    seg->ww_rack_flags &= (u8_t) ~WW_TCP_SEG_LOST;
    /* 0 means "never sent"; a wrapped clock value of 0 is nudged by one millisecond. */
    seg->ww_rack_xmit_ms = now != 0 ? now : 1;
}

void wwTcpRackOnRto(struct tcp_pcb *pcb)
{
    for (struct tcp_seg *seg = pcb->unacked; seg != NULL; seg = seg->next)
    {
        seg->ww_rack_flags &= (u8_t) ~(WW_TCP_SEG_SACKED | WW_TCP_SEG_LOST);
    }
    pcb->ww_rack_sacked_out   = 0;
    pcb->ww_rack_sacked_bytes = 0;
    pcb->ww_rack_lost_bytes   = 0;
    pcb->ww_rack_state &= (u8_t) ~(WW_TCP_RACK_RECOVERY | WW_TCP_RACK_STAMPED | WW_TCP_RACK_PROBED);
}

#endif /* LWIP_TCP && WW_LWIP_TCP_RACK */
