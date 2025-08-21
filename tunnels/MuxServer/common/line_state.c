#include "structure.h"

#include "loggers/network_logger.h"

void muxserverLinestateInitialize(muxserver_lstate_t *ls, line_t *l, bool is_child, cid_t connection_id)
{
    wid_t wid = lineGetWID(l);
    *ls       = (muxserver_lstate_t) {.l              = l,
                                      .parent         = NULL,
                                      .child_prev     = NULL,
                                      .child_next     = NULL,
                                      .read_stream    = bufferstreamCreate(getWorkerBufferPool(wid),kMuxFrameLength),
                                      .connection_id  = connection_id,
                                      .children_count = 0,
                                      .is_child       = is_child,
                                      .paused         = false};
}

void muxserverLinestateDestroy(muxserver_lstate_t *ls)
{
    // Check linked list integrity before destroying
    if (! ls->is_child)
    {
        // If this is a parent, it should not have any children
        if (ls->children_count != 0)
        {
            LOGF("MuxServer: Trying to destroy parent line state with %u children still attached", ls->children_count);
            terminateProgram(1);
        }
        if (ls->child_prev != NULL || ls->child_next != NULL)
        {
            LOGF("MuxServer: Trying to destroy parent line state with child links still present");
            terminateProgram(1);
        }
    }
    else
    {
        // If this is a child, it should not be linked to a parent
        if (ls->parent != NULL)
        {
            LOGF("MuxServer: Trying to destroy child line state while still linked to parent");
            terminateProgram(1);
        }
        // Child should also not be linked to siblings
        if (ls->child_prev != NULL || ls->child_next != NULL)
        {
            LOGF("MuxServer: Trying to destroy child line state while still linked to siblings");
            terminateProgram(1);
        }
    }

    bufferstreamDestroy(&(ls->read_stream));
    memoryZeroAligned32(ls, sizeof(muxserver_lstate_t));
}
