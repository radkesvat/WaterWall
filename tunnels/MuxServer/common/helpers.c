#include "structure.h"

#include "loggers/network_logger.h"

void muxserverJoinConnection(muxserver_lstate_t *parent, muxserver_lstate_t *child)
{

    assert(child && parent && ! child->is_child && parent->is_child == false);
    child->parent   = parent;
    child->is_child = true;

    child->child_next = parent->child_next;
    child->child_prev = NULL;

    if (parent->child_next != NULL)
    {
        parent->child_next->child_prev = child;
    }

    parent->child_next = child;

    parent->children_count++;

    assert(parent->connection_id < CID_MAX);
    child->connection_id = ++parent->connection_id;
}

void muxserverLeaveConnection(muxserver_lstate_t *child)
{
    if (child == NULL || ! child->is_child || child->parent == NULL)
    {
        return;
    }

    if (child->child_prev != NULL)
    {
        child->child_prev->child_next = child->child_next;
    }
    else
    {
        child->parent->child_next = child->child_next;
    }

    if (child->child_next != NULL)
    {
        child->child_next->child_prev = child->child_prev;
    }

    child->parent->children_count--;

    child->parent     = NULL;
    child->child_prev = NULL;
    child->child_next = NULL;
    child->is_child   = false;
}


void muxserverMakeMuxFrame(sbuf_t *buf, cid_t cid, uint8_t flag)
{
    if (sbufGetLength(buf) > 0xFFFF - kMuxFrameLength)
    {
        LOGF("MuxServer: Buffer length exceeds maximum allowed size for MUX frame: %zu", sbufGetLength(buf));
        terminateProgram(1);
    }
    sbufShiftLeft(buf, kMuxFrameLength);

    mux_frame_t frame = {.length = sbufGetLength(buf) - kMuxFrameLength,
                         .cid    = cid, // will be set later
                         .flags  = flag,
                         ._pad1  = 0};
    sbufWrite(buf, &frame, kMuxFrameLength);
}
