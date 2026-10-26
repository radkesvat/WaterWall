#pragma once

#include "line.h"

typedef struct packet_affinity_s packet_affinity_t;

/* One fixed consumer continuation owns one context. Create before publication;
 * destroy only after producers and worker callbacks/messages have settled.
 * The context owns shared fragment storage and per-destination packet FIFOs,
 * never a worker pool. Mutex/fragment resource refusal returns NULL. */
packet_affinity_t *packetAffinityCreate(tunnel_t *tunnel, LineTaskFnWithBuf continuation);
void               packetAffinityDestroy(packet_affinity_t *affinity);

/* Takes the packet on every path. Complete IPv4 TCP/UDP packet-line input resumes
 * on its shared flow-hash worker. Preserved fragments follow their first
 * fragment's transport tuple, with tails staged until that tuple is known.
 * Other protocols, normal lines, and one-worker execution continue inline.
 * The continuation must not repeat decoding. Repair requests travel with each
 * buffer; fragment requests are completed before staging.
 *
 * One FIFO per destination orders all accepted producers, including local and
 * reentrant input. An empty local destination can drain synchronously inside
 * an admitted normal callback, preserving the caller's packet batch. Other
 * delivery is force-queued, with one wakeup per active destination. Drains yield
 * after 256 packets or 256 KiB of payload, each queued drain forming a batch.
 * No original order across independent readers can be reconstructed here.
 *
 * Aggregate retention is bounded to 512 packets and 8 MiB per context, charging
 * sbuf allocation plus queue record through callback return. Fragment staging
 * has separate existing bounds. Capacity refusal drops the new packet; worker
 * message refusal/cancellation drops that destination's accepted FIFO. The
 * caller must invoke Forward on the live source line's event worker. */
void packetAffinityForward(packet_affinity_t *affinity, line_t *source_line, sbuf_t *buf);

typedef enum flow_affinity_direction_e
{
    kFlowAffinityUpstream,
    kFlowAffinityDownstream
} flow_affinity_direction_t;

/* Internal L3 helper, not a JSON-registered node. The owner inserts it during
 * mutable chain construction and destroys it through tunnelOwnedChildDestroy()
 * after runtime callbacks settle. It owns private metadata, but no neighbouring
 * tunnel or line. Payload in the selected direction uses the dispatcher;
 * opposite payload and lifecycle notifications pass through unchanged. Finish
 * first closes the exact packet worker lane and discards its pending payloads;
 * existing task/cancel tokens settle before destruction. */
tunnel_t *flowAffinityTunnelCreate(flow_affinity_direction_t direction);
