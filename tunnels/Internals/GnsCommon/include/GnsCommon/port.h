#pragma once

#include "wwapi.h"

#include "gns_external_transport.h"

/*
 * The part of one GNS session that threads other than its worker may touch.
 *
 * GameNetworkingSockets sends from its own service thread and reports an incoming connection on whatever worker
 * runs its callbacks. None of those threads may use another worker's pool, line or timer. They only reach a port:
 * a leaf lock, a bounded list of copied datagrams, a few flags and a reference count. The session's worker empties
 * it. A port asks for one wake of that worker when something arrives while the worker is not already at it.
 *
 * Lock order: GNS's locks, then the port lock. The port lock is released before the wake is posted, and it is
 * never held around a call into GNS or into a tunnel.
 */

typedef struct gns_port_s gns_port_t;

typedef struct gns_port_datagram_s
{
    struct gns_port_datagram_s *next;
    uint32_t                    length;
    uint8_t                     bytes[];
} gns_port_datagram_t;

/* Runs on the owner worker: something arrived while the session was not looking. */
typedef void (*gns_port_wake_fn)(void *user);

/* Process-wide state behind every port, and the library itself. The first call starts both and the last one stops
 * them. They are called where nodes are created and destroyed, never concurrently. node_type names the caller in
 * the log line of a failure. */
bool gnsRuntimeAcquire(const char *node_type);
void gnsRuntimeRelease(void);

/* The creator owns one reference and is the only one that calls the owner-side functions below. */
gns_port_t *gnsPortCreate(wid_t owner, uint32_t queue_limit, gns_port_wake_fn wake, void *user);
void        gnsPortRelease(gns_port_t *port);
/* Identifies the port to the accept callback through GNS's connection user data. Stale after gnsPortDetach(). */
int64_t gnsPortToken(const gns_port_t *port);

/* For gns_external_endpoint_create_*(): user is the port. Any thread, with GNS locks held. A full list refuses the
 * datagram, and GNS offers its data again a moment later. */
bool gnsPortSend(void *user, const uint8_t *data, size_t length, const gns_external_addr_t *to);

/* Owner worker only. Enter before calling GNS for this session or before draining; while entered, arrivals do not
 * post a wake. Then take what arrived until Leave returns true: it returns false when something arrived since the
 * last Take, and the owner takes again. An owner that has to let other work run first calls Yield instead: it
 * leaves at once, and one wake brings it back if something is waiting.
 * incoming receives the connection that the accept callback admitted, or 0; it keeps its value once set. */
void                 gnsPortEnter(gns_port_t *port);
gns_port_datagram_t *gnsPortTake(gns_port_t *port, uint32_t *incoming);
bool                 gnsPortLeave(gns_port_t *port);
void                 gnsPortYield(gns_port_t *port);
void                 gnsPortDatagramFree(gns_port_datagram_t *datagram);
/* The session ended. Queued datagrams are freed, the token is retired, and nothing is queued or woken afterwards.
 * Release the endpoint that uses this port after detaching it, and the port after that. */
void     gnsPortDetach(gns_port_t *port);
uint64_t gnsPortRefusedDatagrams(gns_port_t *port);
