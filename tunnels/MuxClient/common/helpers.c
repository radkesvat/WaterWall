#include "structure.h"

#include "loggers/network_logger.h"

void muxclientJoinConnection(muxclient_lstate_t *parent, muxclient_lstate_t *child)
{
    assert(child != NULL && parent != NULL && child->is_child && (parent->is_child == false));
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
}

void muxclientLeaveConnection(muxclient_lstate_t *child)
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

bool muxclientCheckConnectionIsExhausted(muxclient_tstate_t *ts, muxclient_lstate_t *ls)
{
    assert(ls->is_child == false);

    if (ls->children_count == CID_MAX)
    {
        LOGE("MuxClient: Connection exhausted, children count reached maximum value: %u", CID_MAX);
        return true; // Connection is exhausted
    }

    if (ts->concurrency_mode == kConcurrencyModeTimer)
    {
        if (wloopNowMS(getWorkerLoop(lineGetWID(ls->l))) < ts->concurrency_duration + ls->creation_epoch)
        {
            return false; // Connection is not exhausted yet
        }
        return true;
    }

    if (ts->concurrency_mode == kConcurrencyModeCounter)
    {
        if (ls->children_count < ts->concurrency_capacity)
        {
            return false; // Connection is not exhausted yet
        }
        return true;
    }

    assert(false);
    return true;
}

void muxclientMakeMuxFrame(sbuf_t *buf, cid_t cid, uint8_t flag)
{
    if (sbufGetLength(buf) > 0xFFFF - kMuxFrameLength)
    {
        LOGF("MuxClient: Buffer length exceeds maximum allowed size for MUX frame: %zu", sbufGetLength(buf));
        terminateProgram(1);
    }

    mux_frame_t frame = {.length = sbufGetLength(buf),
                         .cid    = cid, // will be set later
                         .flags  = flag,
                         ._pad1  = 0};
    sbufShiftLeft(buf, kMuxFrameLength);
    sbufWrite(buf, &frame, kMuxFrameLength);
}
