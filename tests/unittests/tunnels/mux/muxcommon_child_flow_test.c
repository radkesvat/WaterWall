/*
 * Covers: shared Mux child-source reasons, local-hold membership and notifications.
 * Setup: Stack-owned flow entries, parent lists and a live line whose creator
 * reference remains held. Stack tunnels register both directions of Pause/Resume.
 * Cases: all list positions, repeated add/remove, FIFO reinsertion, fatal count
 * underflow, every peer/local/open combination, orientation, suppression, nested
 * transitions and flow retirement. Node-specific attachment and Finish behavior
 * remain in the frame-encoding fixtures.
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

typedef struct notification_probe_s
{
    tunnel_t         *sender;
    tunnel_t         *prev;
    tunnel_t         *next;
    line_t           *child;
    mux_child_flow_t  flow;
    mux_orientation_t orientation;
    unsigned          pauses;
    unsigned          resumes;
    bool              reverse_transition;
    bool              retire;
} notification_probe_t;

static notification_probe_t *probe;

static void syncProbe(bool child_open, bool quiescing)
{
    const uint32_t references = atomicLoadU32Relaxed(&probe->child->refc);
    muxChildFlowSync(probe->sender, probe->child, &probe->flow, child_open, quiescing, probe->orientation);
    require(atomicLoadU32Relaxed(&probe->child->refc) == references,
            "notification leaked its temporary child reference");
}

static void recordNotification(tunnel_t *t, line_t *child, bool pause, bool upstream)
{
    require(t == (probe->orientation == kMuxChildrenTowardPrev ? probe->prev : probe->next) &&
                upstream == (probe->orientation == kMuxChildrenTowardNext),
            "source notification used the wrong neighbor or direction");
    require(child == probe->child && lineIsAlive(child), "source notification changed or destroyed the child");
    require(atomicLoadU32Relaxed(&child->refc) >= 2, "source notification lacks a temporary child reference");
    require(probe->flow.source_pause_notified == pause, "notification latch was not published before dispatch");
    if (pause)
        ++probe->pauses;
    else
        ++probe->resumes;
    if (probe->reverse_transition)
    {
        probe->reverse_transition    = false;
        probe->flow.peer_flow_paused = ! pause;
        syncProbe(true, false);
    }
    if (probe->retire)
        probe->flow = (mux_child_flow_t) {0}; // A borrowed line can outlive this tunnel's retired state.
}

static void recordPauseU(tunnel_t *t, line_t *child)
{
    recordNotification(t, child, true, true);
}
static void recordPauseD(tunnel_t *t, line_t *child)
{
    recordNotification(t, child, true, false);
}
static void recordResumeU(tunnel_t *t, line_t *child)
{
    recordNotification(t, child, false, true);
}
static void recordResumeD(tunnel_t *t, line_t *child)
{
    recordNotification(t, child, false, false);
}

static void testNotifications(void)
{
    const mux_orientation_t orientations[] = {kMuxChildrenTowardPrev, kMuxChildrenTowardNext};
    for (size_t i = 0; i < ARRAY_SIZE(orientations); ++i)
    {
        tunnel_t             sender = {0}, prev = {0}, next = {0};
        line_t               child = {
                          .alive = true, .active_tunnels_mask = {UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX}, .refc = 1};
        notification_probe_t p     = {
                .orientation = orientations[i], .sender = &sender, .prev = &prev, .next = &next, .child = &child};
        probe         = &p;
        sender.prev   = &prev;
        sender.next   = &next;
        prev.fnPauseU = next.fnPauseU = recordPauseU;
        prev.fnPauseD = next.fnPauseD = recordPauseD;
        prev.fnResumeU = next.fnResumeU = recordResumeU;
        prev.fnResumeD = next.fnResumeD = recordResumeD;

        syncProbe(true, false);
        p.flow.peer_flow_paused = true;
        syncProbe(true, false);
        syncProbe(true, false);
        p.flow.parent_write_paused = true;
        p.flow.peer_flow_paused    = false;
        syncProbe(true, false);
        require(p.pauses == 1 && p.resumes == 0, "unchanged effective pressure emitted another notification");
        p.flow.parent_write_paused = false;
        syncProbe(true, false);
        syncProbe(true, false);
        syncProbe(false, false);
        syncProbe(false, false);
        syncProbe(true, false);
        require(p.pauses == 2 && p.resumes == 2, "open/close transitions lost or duplicated a notification");

        p.flow.source_starting  = true;
        p.flow.peer_flow_paused = true;
        syncProbe(true, false);
        require(! p.flow.source_pause_notified, "startup changed the notification latch");
        p.flow.peer_flow_paused = false;
        p.flow.source_starting  = false;
        syncProbe(true, false);
        require(p.pauses == 2 && p.resumes == 2, "startup emitted an obsolete transition");
        p.flow.peer_flow_paused = true;
        syncProbe(true, true);
        require(! p.flow.source_pause_notified, "quiescence changed the notification latch");
        syncProbe(true, false);
        p.flow.peer_flow_paused = false;
        p.flow.source_starting  = true;
        syncProbe(true, false);
        require(p.flow.source_pause_notified, "startup released an emitted Pause");
        p.flow.source_starting = false;
        syncProbe(true, true);
        require(p.flow.source_pause_notified && p.pauses == 3 && p.resumes == 2, "quiescence resumed a producer");
        syncProbe(true, false);
        require(p.resumes == 3, "suppression completion did not reconcile current pressure");

        p.flow.peer_flow_paused = true;
        p.reverse_transition    = true;
        syncProbe(true, false);
        require(! p.flow.source_pause_notified && p.pauses == 4 && p.resumes == 4,
                "outer Pause overwrote the nested Resume");
        p.flow.peer_flow_paused = true;
        syncProbe(true, false);
        p.flow.peer_flow_paused = false;
        p.reverse_transition    = true;
        syncProbe(true, false);
        require(p.flow.source_pause_notified && p.pauses == 6 && p.resumes == 5,
                "outer Resume overwrote the nested Pause");

        p.flow.peer_flow_paused = false;
        syncProbe(true, false);
        p.flow.peer_flow_paused = true;
        p.retire                = true;
        syncProbe(true, false);
        require(! p.flow.peer_flow_paused && ! p.flow.source_pause_notified,
                "notification wrote flow state after callback retirement");
    }
    probe = NULL;
}

int main(void)
{
    TEST_RUN_CASE(testCountUnderflow);
    TEST_RUN_CASE(testHoldMembership);
    TEST_RUN_CASE(testEffectiveState);
    TEST_RUN_CASE(testNotifications);
    puts("muxcommon_child_flow_test: all cases passed");
    return 0;
}
