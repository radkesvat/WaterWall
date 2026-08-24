#include "global_state.h"
#include "local_widle_table.h"

typedef struct idle_test_context_s
{
    local_idle_table_t *table;
    local_idle_item_t  *remove_during_callback;
    unsigned int        id;
} idle_test_context_t;

static unsigned int callback_order[16];
static size_t       callback_order_len;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void recordExpiry(local_idle_item_t *item)
{
    idle_test_context_t *context = item->userdata;
    require(callback_order_len < ARRAY_SIZE(callback_order), "idle callback order overflow");
    callback_order[callback_order_len++] = context->id;
    if (context->remove_during_callback != NULL)
    {
        require(localidletableRemoveIdleItem(context->table, context->remove_during_callback),
                "callback could not immediately remove another idle item");
        context->remove_during_callback = NULL;
    }
}

int main(void)
{
    const uint32_t saved_workers_count = GSTATE.workers_count;
    worker_t      *saved_workers       = GSTATE.workers;
    const bool     saved_initialized   = GSTATE.flag_initialized;

    worker_t workers[2]       = {{0}};
    workers[0].wid            = 0;
    workers[0].has_event_loop = true;
    workers[1].wid            = 1;
    workers[1].has_event_loop = false;
    GSTATE.workers_count      = 2;
    GSTATE.workers            = workers;
    GSTATE.flag_initialized   = true;
    testWorkerBindWID(0);

    wloop_t *loop = wloopCreate(WLOOP_FLAG_AUTO_FREE, NULL, 0);
    require(loop != NULL, "failed to create worker-local idle test loop");
    workers[0].loop = loop;

    local_idle_table_t *table  = localIdleTableCreate(loop);
    idle_test_context_t first  = {.table = table, .id = 1};
    idle_test_context_t second = {.table = table, .id = 2};

    local_idle_item_t *later  = localidletableCreateItem(table, 1, &first, recordExpiry, 300);
    local_idle_item_t *sooner = localidletableCreateItem(table, 2, &second, recordExpiry, 100);
    require(later != NULL && sooner != NULL, "failed to create indexed idle entries");
    require(localidletableCreateItem(table, 2, &second, recordExpiry, 100) == NULL, "duplicate idle key was accepted");

    localidletableKeepIdleItemForAtleast(table, sooner, 400);
    require(localidletableGetItemCount(table) == 2, "deadline extension changed active item count");
    localidletableDrainItems(table);
    require(callback_order_len == 2 && callback_order[0] == 1 && callback_order[1] == 2,
            "deadline extension did not preserve indexed-heap order");
    require(localidletableGetItemCount(table) == 0, "drain retained active idle entries");

    local_idle_item_t *direct = localidletableCreateItem(table, 3, &first, recordExpiry, 300000);
    require(direct != NULL, "failed to create direct-removal item");
    require(localidletableRemoveIdleItem(table, direct), "direct-handle removal failed");
    require(localidletableGetIdleItemByHash(table, 3) == NULL && localidletableGetItemCount(table) == 0,
            "direct removal left a long-deadline tombstone");

    require(localidletableCreateItem(table, 6, &first, recordExpiry, 300000) != NULL,
            "failed to create by-hash removal item");
    require(localidletableRemoveIdleItemByHash(table, 6), "by-hash removal failed");
    require(localidletableGetIdleItemByHash(table, 6) == NULL && localidletableGetItemCount(table) == 0,
            "by-hash removal left an indexed item behind");

    for (uint64_t key = 100; key < 10100; ++key)
    {
        local_idle_item_t *item = localidletableCreateItem(table, key, &first, recordExpiry, 300000);
        require(item != NULL, "high-churn idle insertion failed");
        require(localidletableRemoveIdleItem(table, item), "high-churn direct removal failed");
    }
    require(localidletableGetItemCount(table) == 0, "high-churn table size followed historical rather than live items");

    idle_test_context_t remover      = {.table = table, .id = 3};
    idle_test_context_t removed      = {.table = table, .id = 4};
    callback_order_len               = 0;
    local_idle_item_t *remove_target = localidletableCreateItem(table, 5, &removed, recordExpiry, 500);
    require(remove_target != NULL, "failed to create callback-removal target");
    remover.remove_during_callback = remove_target;
    require(localidletableCreateItem(table, 4, &remover, recordExpiry, 100) != NULL,
            "failed to create callback remover");
    localidletableDrainItems(table);
    require(callback_order_len == 1 && callback_order[0] == 3,
            "callback-driven removal invoked or retained the removed consumer");

    idle_test_context_t quiesced = {.table = table, .id = 5};
    callback_order_len           = 0;
    localidletableTestSetNowMS(table, 1000);
    local_idle_item_t *quiesced_item = localidletableCreateItem(table, 7, &quiesced, recordExpiry, 100);
    require(quiesced_item != NULL, "failed to create quiescence item");
    require(wloopNTimers(loop) == 1, "local idle timer was not armed before quiescence");

    localidletableQuiesce(table);
    require(wloopNTimers(loop) == 0, "local idle timer remained armed after quiescence");
    localidletableTestSetNowMS(table, 1100);
    discard wloopProcessEvents(loop, 0);
    require(callback_order_len == 0, "quiesced table delivered a later natural-expiration callback");
    require(localidletableGetIdleItemByHash(table, 7) == quiesced_item && localidletableGetItemCount(table) == 1,
            "quiescence removed or lost the active idle item");

    localidletableDrainItems(table);
    require(callback_order_len == 1 && callback_order[0] == 5 && localidletableGetItemCount(table) == 0,
            "owner drain did not settle the quiesced item exactly once");
    localidletableDestroy(table);
    wloopDestroy(&loop);

    testWorkerUnbindWID();
    GSTATE.workers_count    = saved_workers_count;
    GSTATE.workers          = saved_workers;
    GSTATE.flag_initialized = saved_initialized;

    printf("local_idle_table_indexed_test: all cases passed\n");
    return 0;
}
