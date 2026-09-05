#include "structure.h"

#include "loggers/network_logger.h"

void muxserverLinestateInitialize(tunnel_t *t, muxserver_lstate_t *ls, line_t *l, bool is_child,
                                  mux_cid_t connection_id)
{
    wid_t                     wid          = lineGetWID(l);
    muxserver_parent_state_t *parent_state = NULL;
    if (! is_child)
    {
        parent_state = memoryAllocateZero(sizeof(*parent_state));
        if (UNLIKELY(parent_state == NULL))
        {
            LOGF("MuxServer: failed to allocate parent-only state");
            abortProgramNow(1);
        }
        parent_state->child_map               = muxserver_child_map_t_init();
        parent_state->rejection_bucket.tokens = kMuxServerRejectedOpenBurst;
    }

    *ls = (muxserver_lstate_t) {.t                  = t,
                                .l                  = l,
                                .parent             = NULL,
                                .child_prev         = NULL,
                                .child_next         = NULL,
                                .detached_prev      = NULL,
                                .detached_next      = NULL,
                                .read_stream        = bufferstreamCreate(getWorkerBufferPool(wid), kMuxFrameLength),
                                .pending_child_data = bufferqueueCreate(kMuxChildBufferQueueCap),
                                .pending_child_queue_charge = 0,
                                .connection_id              = connection_id,
                                .close_state                = kMuxServerChildCloseOpen,
                                .children_count             = 0,
                                .parent_state               = parent_state,
                                .child_idle_item            = NULL,
                                .is_child                   = is_child,
                                .paused                     = false,
                                .flow_paused_sent           = false,
                                .peer_flow_paused           = false,
                                .parent_write_paused        = false,
                                .parent_finishing           = false,
                                .detached_registered        = false,
                                .child_slot_reserved        = false,
                                .child_has_payload_activity = false};
}

void muxserverLinestateDestroy(tunnel_t *t, muxserver_lstate_t *ls)
{
    // Check linked list integrity before destroying
    if (! ls->is_child)
    {
        // If this is a parent, it should not have any children
        if (ls->children_count != 0)
        {
            LOGF("MuxServer: Trying to destroy parent line state with %u children still attached", ls->children_count);
            abortProgramNow(1);
        }
        if (ls->child_prev != NULL || ls->child_next != NULL)
        {
            LOGF("MuxServer: Trying to destroy parent line state with child links still present");
            abortProgramNow(1);
        }
        if (ls->pending_child_queue_charge != 0)
        {
            LOGF("MuxServer: Trying to destroy parent line state with %zu retained child-queue charge",
                 ls->pending_child_queue_charge);
            abortProgramNow(1);
        }
        if (ls->parent_state == NULL || muxserver_child_map_t_size(&ls->parent_state->child_map) != 0)
        {
            LOGF("MuxServer: Trying to destroy parent line state with a nonempty or absent CID index");
            abortProgramNow(1);
        }
    }
    else
    {
        // If this is a child, it should not be linked to a parent
        if (ls->parent != NULL)
        {
            LOGF("MuxServer: Trying to destroy child line state while still linked to parent");
            abortProgramNow(1);
        }
        // Child should also not be linked to siblings
        if (ls->child_prev != NULL || ls->child_next != NULL)
        {
            LOGF("MuxServer: Trying to destroy child line state while still linked to siblings");
            abortProgramNow(1);
        }
        if (ls->detached_registered || ls->detached_prev != NULL || ls->detached_next != NULL)
        {
            LOGF("MuxServer: Trying to destroy child line state while still registered as detached");
            abortProgramNow(1);
        }
        if (ls->parent_state != NULL)
        {
            LOGF("MuxServer: child line state unexpectedly owns parent-only state");
            abortProgramNow(1);
        }
        if (ls->pending_child_queue_charge != 0)
        {
            LOGF("MuxServer: Trying to destroy child line state with %zu retained queue charge",
                 ls->pending_child_queue_charge);
            abortProgramNow(1);
        }
        if (ls->child_idle_item != NULL)
        {
            muxserver_worker_state_t *worker_state = muxserverGetWorkerState(t, ls->l);
            local_idle_item_t        *idle_item    = ls->child_idle_item;
            ls->child_idle_item                    = NULL;
            if (worker_state->child_idle_table == NULL ||
                ! localidletableRemoveIdleItem(worker_state->child_idle_table, idle_item))
            {
                LOGF("MuxServer: child idle item was absent during line-state destruction");
                abortProgramNow(1);
            }
        }
        if (ls->child_slot_reserved)
        {
            ls->child_slot_reserved = false;
            muxserverReleaseLiveChildSlot(tunnelGetState(t));
        }
    }

    if (! ls->is_child)
    {
        muxserver_child_map_t_drop(&ls->parent_state->child_map);
        memoryFree(ls->parent_state);
        ls->parent_state = NULL;
    }
    bufferstreamDestroy(&(ls->read_stream));
    bufferqueueDestroy(&(ls->pending_child_data));
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(muxserver_lstate_t)));
}
