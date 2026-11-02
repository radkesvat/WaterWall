#pragma once

#include "tunnel.h"

/* Owner-worker state embedded in a child. Links borrow the containing state;
 * membership is a local pressure reason, independent of peer pressure and the
 * last notification. Unlink before detaching or destroying the child. */
typedef struct mux_child_flow_s
{
    struct mux_child_flow_s *hold_prev;
    struct mux_child_flow_s *hold_next;
    bool                     peer_flow_paused : 1;      // Peer requested the child's producer pause.
    bool                     parent_write_paused : 1;   // Membership in the parent's local hold FIFO.
    bool                     source_pause_notified : 1; // Last effective state emitted to the producer.
    bool                     source_starting : 1;       // Defer notifications until source Init/Est returns.
} mux_child_flow_t;

typedef struct mux_hold_list_s
{
    mux_child_flow_t *head;
    mux_child_flow_t *tail;
    uint32_t          count;
} mux_hold_list_t;

/* Callback-free, allocation-free FIFO operations. Add requires an attached,
 * open child. A held child belongs to exactly one list; Remove requires that
 * same list. Repeated Add/Remove preserve membership and notification state. */
void muxHoldAdd(mux_hold_list_t *list, mux_child_flow_t *child);
void muxHoldRemove(mux_hold_list_t *list, mux_child_flow_t *child);
bool muxChildSourcePaused(const mux_child_flow_t *child, bool child_open);

typedef enum mux_orientation_e
{
    kMuxChildrenTowardPrev,
    kMuxChildrenTowardNext,
} mux_orientation_t;

/* Caller supplies a live child and its owner-worker quiescence state. Startup
 * and quiescence leave the notification latch unchanged. A transition publishes
 * the latch before dispatch and retains the child across one Pause/Resume.
 * Nested changes remain authoritative; no flow/state access follows dispatch.
 * Orientation selects notification direction only, never lifecycle ownership.
 * Callers that continue using a separate parent must retain/check it themselves. */
void muxChildFlowSync(tunnel_t *t, line_t *child_l, mux_child_flow_t *flow, bool child_open, bool quiescing,
                      mux_orientation_t orientation);
