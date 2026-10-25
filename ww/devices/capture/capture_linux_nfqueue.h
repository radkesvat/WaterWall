#pragma once
#include "capture_linux_private.h"

typedef enum netfilter_packet_result_e
{
    kNetfilterPacketError = -1,
    kNetfilterPacketWouldBlock,
    kNetfilterPacketYield,
    kNetfilterPacketEof,
    kNetfilterPacketAccepted,
    kNetfilterPacketDiscarded,
    kNetfilterPacketMalformedDiscarded,
    kNetfilterPacketReady
} netfilter_packet_result_t;

typedef enum netfilter_verdict_result_e
{
    kNetfilterVerdictError = -1,
    kNetfilterVerdictWouldBlock,
    kNetfilterVerdictYield,
    kNetfilterVerdictSent
} netfilter_verdict_result_t;

/* Both operations are nonblocking, retain caller ownership of buf and never
 * poll. Ready/Discarded/MalformedDiscarded mean one packet was consumed and
 * packet_id receives its network-order id: the caller owes a verdict even for
 * discarded input. Ready exposes the validated IP packet in buf. Other results
 * leave packet_id unchanged and owe no verdict. Yield bounds interrupted
 * syscalls and requires an explicit continuation, without a readiness edge.
 *
 * Keep the packet, id and selected host-order verdict until Sent; no packet may
 * be published before that result. WouldBlock needs writable readiness, Yield
 * needs a continuation, and the owner enforces its absolute verdict deadline. */
netfilter_packet_result_t  netfilterReceivePacket(int netfilter_socket, sbuf_t *buf, uint32_t *packet_id);
netfilter_verdict_result_t netfilterTrySendVerdict(int netfilter_socket, uint16_t qnumber, uint32_t packet_id,
                                                   uint32_t verdict);

/* Acknowledged setup and bounded coordinator-only cleanup. Do not call the
 * blocking GetPacket wrappers from an event-worker receive callback. */
bool                      netfilterSetConfig(int netfilter_socket, uint8_t cmd, uint16_t qnum, uint16_t pf);
bool                      netfilterSetParams(int netfilter_socket, uint16_t qnumber, uint8_t mode, uint32_t range);
bool                      netfilterSetQueueLength(int netfilter_socket, uint16_t qnumber, uint32_t qlen);
netfilter_packet_result_t netfilterGetPacketUntil(capture_device_t *cdev, int netfilter_socket, uint16_t qnumber,
                                                  sbuf_t *buff, uint64_t verdict_deadline_us);
netfilter_packet_result_t netfilterGetPacket(capture_device_t *cdev, int netfilter_socket, uint16_t qnumber,
                                             sbuf_t *buff);
