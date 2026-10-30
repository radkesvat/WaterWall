#pragma once

/*
 * Consumer flow selection and independent packet-device receive distribution.
 */

#include "devices/device_flow_hash.h"
#include "devices/device_reader_session.h"

/*
 * Selects the same worker for both directions of a parseable IP flow. This is
 * exactly deviceFlowWorkerHash() reduced modulo the worker count. Returns
 * false for malformed or unsupported packets so callers can retain their
 * round-robin fallback.
 */
bool deviceFlowAffineWID(const uint8_t *packet, uint32_t length, wid_t *out_wid);

/*
 * Select a processing worker independently of transport ownership. Multiple
 * native readers keep their own worker. A single reader keeps visible TCP/UDP
 * tuples on a stable worker and applies the session's resolved opaque IPv4
 * policy. Spread and unsupported input rotate through the session's event
 * workers. This is receive locality, not proof of consumer flow ownership.
 * Call once per admitted native record,
 * retaining the result across capacity retries and all segments of that record.
 */
wid_t deviceReaderSelectWID(device_reader_session_t *session, wid_t reader_wid, uint16_t reader_count,
                            const sbuf_t *buf);

/*
 * Takes ownership of every buffer and posts one batch per selected worker.
 * Complete native TCP/UDP packets retain tuple-based receive locality; opaque
 * IPv4 follows the resolved session policy. Preserved
 * fragments retain their fragment association. A refused post drops
 * and settles the affected work locally; queue pressure is not a process-wide
 * failure.
 */
void deviceReaderDistributeBatch(device_reader_session_t *session, sbuf_t **bufs, unsigned int count);

/* Nonblocking variant for readers without a capacity-wait mechanism. Requires
 * a configured byte/packet budget and worker FIFO. Takes every buffer; when
 * capacity is exhausted, drops the unadmitted remainder of the read batch.
 * Accepted packets retain their per-worker order. The caller owns only its
 * finite read batch and fragment staging outside the dispatch budget. */
void deviceReaderDistributeBatchDroppingOverflow(device_reader_session_t *session, sbuf_t **bufs, unsigned int count);

/* TUN GSO output is already segmented into unfragmented IP packets.
 * Post it with native receive locality and stable per-worker bucket ordering,
 * transferring each buffer's pre-allocation budget reservation as well.
 * Optional prepare completes private packet work on the destination worker
 * before delivery; see DeviceReaderPrepareFn. */
void deviceReaderDistributeGsoBatch(device_reader_session_t *session, sbuf_t **bufs, const size_t *charges,
                                    unsigned int count, DeviceReaderPrepareFn prepare);
