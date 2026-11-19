#pragma once
#include "wwapi.h"

WW_EXPORT node_t nodePacketsToConnectionGet(void);

/* Optional private-pipeline provenance guard. Bound before Start; constant work,
 * thread safe, no allocation or neighbouring callbacks. Its lock order must be
 * compatible with owner-worker protocol callbacks. Zero denies.
 * A nonzero epoch must never be reused for a different source identity. */
typedef uint64_t (*ptc_source_epoch_fn)(void *context, const ip_addr_t *source);
WW_EXPORT void ptcSetSourceEpochProvider(tunnel_t *t, void *context, ptc_source_epoch_fn provider);
/* Owner-worker metadata for the exact PTC-owned normal line. */
WW_EXPORT uint64_t ptcLineSourceEpoch(tunnel_t *t, line_t *line);
WW_EXPORT bool     ptcLineIsDatagram(tunnel_t *t, line_t *line);
/* Close admission in the provider before calling from the coordinator event
 * worker. Completion runs there only after every owner has retired matching
 * TCP/UDP lines and protocol state. callback(true) is a reuse barrier. A false
 * result (including cancellation) keeps ranges closed. Context must outlive all
 * worker messages. Deferred packets/output retain and validate their epoch. */
typedef void (*ptc_retire_complete_fn)(void *context, bool completed);
WW_EXPORT void ptcRetireSourceRange(tunnel_t *t, const ip_addr_t *network, const ip_addr_t *mask, wid_t coordinator,
                                    ptc_retire_complete_fn callback, void *context);
