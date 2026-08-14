#pragma once

/*
 * A fragmented device packet carries one settlement claim with its sbuf
 * ownership until a terminal consumer proves the exact lwIP residue state or
 * the buffer is discarded.  Duplicated sbufs share a counted claim; the
 * fragment-affinity publication settles once, after the last copy resolves.
 */

#include "shiftbuffer.h"
#include "wlibc.h"

typedef struct device_reader_session_s            device_reader_session_t;
typedef struct device_frag_claim_s                device_frag_claim_t;
typedef struct device_frag_affinity_publication_s device_frag_affinity_publication_t;

typedef enum device_frag_settlement_e
{
    /* No terminal consumer proved the stack's exact state. */
    kDeviceFragSettlementUnknown = 0,

    /* The exact key is present in lwIP's reassembly table after input. */
    kDeviceFragSettlementResiduePresent,

    /* The exact key is absent after completion, rejection, or an exact purge. */
    kDeviceFragSettlementNoResidue
} device_frag_settlement_t;

/* Creates and attaches one claim. On failure the buffer remains unmodified. */
bool deviceFragClaimAttach(device_reader_session_t *session, uint32_t generation,
                           const device_frag_affinity_publication_t *publication, sbuf_t *buf);

/* A tracked late-generation or poisoned packet must not be admitted to lwIP. */
bool deviceFragClaimMayEnterStack(const sbuf_t *buf);

/* A transform may change payload bytes, but not the claimed reassembly key. */
bool deviceFragClaimPacketMatches(const sbuf_t *buf);

/*
 * Pins generation admission from the final pre-input check until lwIP has
 * returned and the exact residue query is complete. `claim_out` is borrowed
 * from the buffer and remains valid until the matching End call.
 */
bool deviceFragClaimBeginStackUse(const sbuf_t *buf, device_frag_claim_t **claim_out);
/*
 * The ownership-transfer mirror used by asynchronous terminal consumers.
 * `NULL` is an ordinary untracked packet and succeeds without taking a gate.
 */
bool deviceFragClaimBeginTakenStackUse(device_frag_claim_t *claim);
void deviceFragClaimEndStackUse(device_frag_claim_t *claim);

/* Transfer the claim out of a buffer before a terminal owner can free it. */
device_frag_claim_t *deviceFragClaimTake(sbuf_t *buf);

/* Resolve a taken claim, or detach and resolve the claim still on a buffer. */
void deviceFragClaimResolve(device_frag_claim_t *claim, device_frag_settlement_t settlement);
void deviceFragClaimResolveBuffer(sbuf_t *buf, device_frag_settlement_t settlement);
