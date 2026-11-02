#include "MuxCommon/mux_child_flow.h"

#include "loggers/network_logger.h"

void muxHoldAdd(mux_hold_list_t *list, mux_child_flow_t *child)
{
    assert(list != NULL && child != NULL);
    if (child->parent_write_paused)
        return;
    assert(child->hold_prev == NULL && child->hold_next == NULL);
    child->hold_prev = list->tail;
    if (list->tail)
        list->tail->hold_next = child;
    else
        list->head = child;
    list->tail = child;
    list->count++;
    child->parent_write_paused = true;
}

void muxHoldRemove(mux_hold_list_t *list, mux_child_flow_t *child)
{
    assert(list != NULL && child != NULL);
    if (! child->parent_write_paused)
        return;
    if (UNLIKELY(list->count == 0))
    {
        LOGF("Mux: local hold count underflow");
        abortProgramNow(1);
    }
    if (child->hold_prev)
        child->hold_prev->hold_next = child->hold_next;
    else
    {
        assert(list->head == child);
        list->head = child->hold_next;
    }
    if (child->hold_next)
        child->hold_next->hold_prev = child->hold_prev;
    else
    {
        assert(list->tail == child);
        list->tail = child->hold_prev;
    }
    list->count--;
    child->hold_prev = child->hold_next = NULL;
    child->parent_write_paused          = false;
}

bool muxChildSourcePaused(const mux_child_flow_t *child, bool child_open)
{
    assert(child != NULL);
    return child->peer_flow_paused || child->parent_write_paused || ! child_open;
}
