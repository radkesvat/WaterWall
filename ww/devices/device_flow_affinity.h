#pragma once

/*
 * Flow-affine worker selection and bucketed dispatch for packet-device readers.
 */

#include "devices/device_flow_hash.h"
#include "devices/device_reader_session.h"

/*
 * Selects the same worker for both directions of a parseable IP flow. This is
 * exactly deviceFlowAffinityHash() reduced modulo the worker count. Returns
 * false for malformed or unsupported packets so callers can retain their
 * round-robin fallback.
 */
bool deviceFlowAffineWID(const uint8_t *packet, uint32_t length, wid_t *out_wid);

/*
 * Takes ownership of every buffer and posts one batch per selected worker.
 * Parseable IP packets are flow-affine; other packets retain round-robin
 * distribution. A refused post drops and settles the affected work locally;
 * queue pressure is not a process-wide failure.
 */
void deviceFlowAffinityPostBatch(device_reader_session_t *session, sbuf_t **bufs, unsigned int count);

/* TUN GSO output is already segmented into unfragmented IP packets.
 * Post it with the ordinary flow hash and stable per-worker bucket ordering,
 * transferring each buffer's pre-allocation budget reservation as well.
 * Optional prepare completes private packet work on the destination worker
 * before delivery; see DeviceReaderPrepareFn. */
void deviceFlowAffinityPostGsoBatch(device_reader_session_t *session, sbuf_t **bufs, const size_t *charges,
                                    unsigned int count, DeviceReaderPrepareFn prepare);
