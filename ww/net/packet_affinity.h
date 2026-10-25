#pragma once

#include "line.h"

typedef struct packet_affinity_s packet_affinity_t;

/* One decoder continuation owns one context. Create before publication; destroy
 * after worker callbacks/messages settle. The context owns bounded shared
 * fragment storage, never a worker pool. Resource refusal returns NULL. */
packet_affinity_t *packetAffinityCreate(tunnel_t *tunnel, LineTaskFnWithBuf continuation);
void               packetAffinityDestroy(packet_affinity_t *affinity);

/* Takes the decoded packet on every path. TCP/UDP packet-line input resumes on
 * its shared flow-hash worker; preserved fragments follow their first fragment's
 * transport tuple, with tails staged until that tuple is known. Other protocols,
 * normal lines, and one-worker execution continue inline. The continuation must
 * not repeat decoding. A checksum request travels with its packet; for staged
 * fragments it is completed before storage. */
void packetAffinityForward(packet_affinity_t *affinity, line_t *source_line, sbuf_t *buf);
