#pragma once

/*
 * Flow-affine worker selection and bucketed dispatch for packet-device readers.
 */

#include "devices/device_reader_session.h"

/*
 * Selects the same worker for both directions of a parseable IP flow. Returns
 * false for malformed or unsupported packets so callers can retain their
 * round-robin fallback.
 */
bool deviceFlowAffineWID(const uint8_t *packet, uint32_t length, wid_t *out_wid);

/*
 * Takes ownership of every buffer and posts one batch per selected worker.
 * Parseable IP packets are flow-affine; other packets retain round-robin
 * distribution.
 */
void deviceFlowAffinityPostBatch(device_reader_session_t *session, sbuf_t **bufs, unsigned int count);
