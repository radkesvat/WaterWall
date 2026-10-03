#include "structure.h"

#include "loggers/network_logger.h"

void muxclientLinestateInitialize(tunnel_t *t, muxclient_lstate_t *ls, line_t *l, bool is_child,
                                  mux_cid_t connection_id)
{
    discard                   t;
    wid_t                     wid          = lineGetWID(l);
    muxclient_parent_state_t *parent_state = NULL;
    if (! is_child)
    {
        parent_state = memoryAllocateZero(sizeof(*parent_state));
        if (UNLIKELY(parent_state == NULL))
        {
            LOGF("MuxClient: failed to allocate parent-only state");
            abortProgramNow(1);
        }
        parent_state->read_stream = splicestreamCreate(lineGetBufferPool(l), kMuxFrameLength);
        if (UNLIKELY(parent_state->read_stream == NULL))
        {
            LOGF("MuxClient: failed to allocate parent stream");
            abortProgramNow(1);
        }
        bufferqueueInitEmpty(&parent_state->output.pending);
        parent_state->child_map = muxclient_child_map_t_init();
    }
    *ls = (muxclient_lstate_t) {.l                          = l,
                                .parent                     = NULL,
                                .child_prev                 = NULL,
                                .child_next                 = NULL,
                                .pending_child_data         = bufferqueueCreate(kMuxChildBufferQueueCap),
                                .pending_child_queue_charge = 0,
                                .creation_epoch             = is_child ? 0 : wloopNowMS(getWorkerLoop(wid)),
                                .connection_id              = connection_id,
                                .close_state                = kMuxClientChildCloseOpen,
                                .children_count             = 0,
                                .parent_state               = parent_state,
                                .is_child                   = is_child,
                                .paused                     = false,
                                .flow_paused_sent           = false,
                                .peer_flow_paused           = false,
                                .parent_write_paused        = false,
                                .local_hold_prev            = NULL,
                                .local_hold_next            = NULL,
                                .source_pause_notified      = false,
                                .source_starting            = false,
                                .parent_finishing           = false,
                                .open_frame_submitted       = ! is_child,
                                .selection_retired          = false};
}

void muxclientLinestateDestroy(muxclient_lstate_t *ls)
{
    if (UNLIKELY(ls->parent_write_paused || ls->local_hold_prev || ls->local_hold_next ||
                 (! ls->is_child && ls->parent_state &&
                  (ls->parent_state->local_hold_count || ls->parent_state->local_hold_head ||
                   ls->parent_state->local_hold_tail))))
    {
        LOGF("MuxClient: destroying state with local source holds still linked");
        abortProgramNow(1);
    }
    // Check linked list integrity before destroying
    if (! ls->is_child)
    {
        if (ls->parent_state != NULL && ls->parent_state->owned)
        {
            LOGF("MuxClient: destroying a published owned parent");
            abortProgramNow(1);
        }
        // If this is a parent, it should not have any children
        if (ls->children_count != 0)
        {
            LOGF("MuxClient: Trying to destroy parent line state with %u children still attached", ls->children_count);
            abortProgramNow(1);
        }
        if (ls->child_prev != NULL || ls->child_next != NULL)
        {
            LOGF("MuxClient: Trying to destroy parent line state with child links still present");
            abortProgramNow(1);
        }
        if (ls->pending_child_queue_charge != 0)
        {
            LOGF("MuxClient: Trying to destroy parent line state with %zu retained child-queue charge",
                 ls->pending_child_queue_charge);
            abortProgramNow(1);
        }
        if (ls->parent_state == NULL || muxclient_child_map_t_size(&ls->parent_state->child_map) != 0)
        {
            LOGF("MuxClient: Trying to destroy parent line state with a nonempty or absent CID index");
            abortProgramNow(1);
        }
    }
    else
    {
        // If this is a child, it should not be linked to a parent
        if (ls->parent != NULL)
        {
            LOGF("MuxClient: Trying to destroy child line state while still linked to parent");
            abortProgramNow(1);
        }
        // Child should also not be linked to siblings
        if (ls->child_prev != NULL || ls->child_next != NULL)
        {
            LOGF("MuxClient: Trying to destroy child line state while still linked to siblings");
            abortProgramNow(1);
        }
        if (ls->parent_state != NULL)
        {
            LOGF("MuxClient: child line state unexpectedly owns parent-only state");
            abortProgramNow(1);
        }
        if (ls->pending_child_queue_charge != 0)
        {
            LOGF("MuxClient: Trying to destroy child line state with %zu retained queue charge",
                 ls->pending_child_queue_charge);
            abortProgramNow(1);
        }
    }

    if (! ls->is_child)
    {
        muxParentOutputDestroy(&ls->parent_state->output, lineGetBufferPool(ls->l));
        muxclient_child_map_t_drop(&ls->parent_state->child_map);
        splicestreamDestroy(ls->parent_state->read_stream);
        memoryFree(ls->parent_state);
        ls->parent_state = NULL;
    }
    bufferqueueDestroy(&(ls->pending_child_data));
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(muxclient_lstate_t)));
}
