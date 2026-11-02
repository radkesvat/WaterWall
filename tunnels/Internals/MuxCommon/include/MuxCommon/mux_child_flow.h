#pragma once

#include "wlibc.h"

/* Owner-worker state embedded in a child. Links borrow the containing state;
 * membership is a local pressure reason, independent of peer pressure and the
 * last notification. Unlink before detaching or destroying the child. */
typedef struct mux_child_flow_s
{
    struct mux_child_flow_s *hold_prev;
    struct mux_child_flow_s *hold_next;
    bool                     peer_flow_paused : 1;
    bool                     parent_write_paused : 1;
    bool                     source_pause_notified : 1;
    bool                     source_starting : 1;
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
