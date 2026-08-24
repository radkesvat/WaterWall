#include "MuxClient/structure.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

int main(void)
{
    enum
    {
        kChildren = 4096,
    };
    muxclient_parent_state_t parent_state = {.child_map = muxclient_child_map_t_init()};
    muxclient_lstate_t       parent       = {.parent_state = &parent_state};
    muxclient_lstate_t      *children     = memoryAllocateZero(sizeof(*children) * kChildren);
    require(children != NULL, "failed to allocate client CID fixture");

    for (uint32_t i = 0; i < kChildren; ++i)
    {
        children[i].is_child      = true;
        children[i].connection_id = (i * 104729U) + 17U;
        muxclientJoinConnection(&parent, &children[i]);
    }
    require(parent.children_count == kChildren && muxclient_child_map_t_size(&parent_state.child_map) == kChildren,
            "client map/list/count join invariant failed");
    for (uint32_t i = 0; i < kChildren; ++i)
    {
        require(muxclientFindChildByConnectionId(&parent, children[i].connection_id) == &children[i],
                "client CID index resolved the wrong child");
    }
    for (uint32_t i = 1; i < kChildren; i += 2)
    {
        muxclientLeaveConnection(&children[i]);
    }
    for (uint32_t i = 0; i < kChildren; i += 2)
    {
        muxclientLeaveConnection(&children[i]);
    }
    require(parent.children_count == 0 && parent.child_next == NULL &&
                muxclient_child_map_t_size(&parent_state.child_map) == 0,
            "client arbitrary removals broke map/list/count agreement");

    muxclient_child_map_t_drop(&parent_state.child_map);
    memoryFree(children);
    printf("muxclient_cid_index_test: all cases passed\n");
    return 0;
}
