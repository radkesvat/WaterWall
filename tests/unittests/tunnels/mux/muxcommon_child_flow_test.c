/*
 * Covers: shared Mux child-source reasons and local-hold membership.
 * Setup: Stack-owned flow entries and parent lists; the helper borrows all entries.
 * Cases: all list positions, repeated add/remove, FIFO reinsertion, fatal count
 * underflow, and every peer/local/open combination. Node-specific attachment,
 * producer startup and Finish behavior remain in the frame-encoding fixtures.
 * CTest: waterwall.muxcommon_child_flow_unit
 */
#include "MuxCommon/mux_child_flow.h"
#include "loggers/network_logger.h"
#include "wwapi.h"

#include "test_assert.h"

#ifdef OS_LINUX
#include <sys/wait.h>
#include <unistd.h>
#endif

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static void requireList(const mux_hold_list_t *list, mux_child_flow_t *const *entries, uint32_t count)
{
    require(list->count == count, "local hold count differs from membership");
    require(list->head == (count ? entries[0] : NULL), "local hold head differs from insertion order");
    require(list->tail == (count ? entries[count - 1] : NULL), "local hold tail differs from insertion order");
    for (uint32_t i = 0; i < count; ++i)
    {
        require(entries[i]->parent_write_paused, "held entry lost its local pressure reason");
        require(entries[i]->hold_prev == (i ? entries[i - 1] : NULL), "local hold previous link is broken");
        require(entries[i]->hold_next == (i + 1 < count ? entries[i + 1] : NULL), "local hold next link is broken");
    }
}

static void requireUnlinked(const mux_child_flow_t *child)
{
    require(! child->parent_write_paused && child->hold_prev == NULL && child->hold_next == NULL,
            "removed child retained local hold membership or links");
}

static void testHoldMembership(void)
{
    mux_hold_list_t  list = {0};
    mux_child_flow_t a = {0}, b = {0}, c = {0}, d = {0};
    requireList(&list, NULL, 0);
    muxHoldRemove(&list, &a);
    requireUnlinked(&a);
    requireList(&list, NULL, 0);

    muxHoldAdd(&list, &a);
    muxHoldAdd(&list, &a);
    requireList(&list, (mux_child_flow_t *[]) {&a}, 1);
    muxHoldRemove(&list, &a);
    muxHoldRemove(&list, &a);
    requireUnlinked(&a);
    requireList(&list, NULL, 0);

    muxHoldAdd(&list, &a);
    muxHoldAdd(&list, &b);
    muxHoldAdd(&list, &c);
    muxHoldAdd(&list, &d);
    muxHoldAdd(&list, &b);
    requireList(&list, (mux_child_flow_t *[]) {&a, &b, &c, &d}, 4);
    muxHoldRemove(&list, &b);
    requireUnlinked(&b);
    requireList(&list, (mux_child_flow_t *[]) {&a, &c, &d}, 3);
    muxHoldRemove(&list, &a);
    requireUnlinked(&a);
    requireList(&list, (mux_child_flow_t *[]) {&c, &d}, 2);
    muxHoldRemove(&list, &d);
    requireUnlinked(&d);
    requireList(&list, (mux_child_flow_t *[]) {&c}, 1);
    muxHoldAdd(&list, &b);
    requireList(&list, (mux_child_flow_t *[]) {&c, &b}, 2);
    muxHoldRemove(&list, &c);
    muxHoldRemove(&list, &b);
    requireList(&list, NULL, 0);

    // An unlinked entry can join another parent without retaining old links.
    mux_hold_list_t other = {0};
    muxHoldAdd(&other, &b);
    requireList(&other, (mux_child_flow_t *[]) {&b}, 1);
    requireList(&list, NULL, 0);
    muxHoldRemove(&other, &b);
    requireUnlinked(&b);
    requireList(&other, NULL, 0);
}

static void testEffectiveState(void)
{
    for (unsigned peer = 0; peer < 2; ++peer)
        for (unsigned local = 0; local < 2; ++local)
            for (unsigned open = 0; open < 2; ++open)
            {
                mux_child_flow_t child = {.peer_flow_paused = peer != 0, .parent_write_paused = local != 0};
                require(muxChildSourcePaused(&child, open != 0) == (peer || local || ! open),
                        "effective source state omitted a pressure or close reason");
            }

    for (unsigned notified = 0; notified < 2; ++notified)
    {
        mux_hold_list_t  list  = {0};
        mux_child_flow_t child = {
            .peer_flow_paused = true, .source_pause_notified = notified != 0, .source_starting = true};
        muxHoldAdd(&list, &child);
        require(child.peer_flow_paused && child.source_pause_notified == (notified != 0) && child.source_starting,
                "adding a local hold changed an independent flow field");
        child.peer_flow_paused = false;
        require(muxChildSourcePaused(&child, true), "peer Resume bypassed a local hold");
        child.peer_flow_paused = true;
        muxHoldRemove(&list, &child);
        require(child.peer_flow_paused && child.source_pause_notified == (notified != 0) && child.source_starting,
                "removing a local hold changed an independent flow field");
        require(muxChildSourcePaused(&child, true), "local release bypassed peer pressure");
        child.peer_flow_paused = false;
        require(! muxChildSourcePaused(&child, true), "released open child remained paused");
        require(muxChildSourcePaused(&child, false), "closing child resumed its source");
    }
}

static void testCountUnderflow(void)
{
#ifdef OS_LINUX
    const pid_t child = fork();
    require(child >= 0, "failed to fork local hold underflow case");
    if (child == 0)
    {
        if (createNetworkLogger(NULL, true) == NULL)
            _Exit(66);
        mux_child_flow_t entry = {.parent_write_paused = true};
        mux_hold_list_t  list  = {.head = &entry, .tail = &entry};
        muxHoldRemove(&list, &entry);
        _Exit(67);
    }
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 1,
            "local hold count underflow was not fatal");
#endif
}

int main(void)
{
    TEST_RUN_CASE(testCountUnderflow);
    TEST_RUN_CASE(testHoldMembership);
    TEST_RUN_CASE(testEffectiveState);
    puts("muxcommon_child_flow_test: all cases passed");
    return 0;
}
