/* Concurrent envelope parsing and thread-local cJSON error correlation. One
 * thread's failed parse cannot replace another's error pointer. Both threads
 * repeatedly parse valid/invalid input with the process's unchanged allocator.
 * CTest: waterwall.api_json_threads_unit. */
#include "wwapi.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static atomic_bool other_parsed;
static atomic_bool start_race;
static const char  first_invalid[]  = "{\"first\":?}";
static const char  second_invalid[] = "[true,?]";

static void parseRepeatedly(const char *invalid)
{
    for (size_t i = 0; i < 10000; ++i)
    {
        cJSON *value = cJSON_Parse("{\"id\":\"request\",\"body\":\"{}\"}");
        require(value != NULL, "parallel valid JSON parse failed");
        cJSON_Delete(value);
        require(cJSON_Parse(invalid) == NULL, "parallel invalid JSON parse succeeded");
        const char *error = cJSON_GetErrorPtr();
        require((uintptr_t) error >= (uintptr_t) invalid && (uintptr_t) error < (uintptr_t) invalid + strlen(invalid),
                "parallel parser error belongs to another thread");
    }
}

static WTHREAD_ROUTINE(parseOtherThread)
{
    discard userdata;
    require(cJSON_Parse(second_invalid) == NULL, "second invalid JSON parse succeeded");
    const char *error = cJSON_GetErrorPtr();
    require((uintptr_t) error >= (uintptr_t) second_invalid &&
                (uintptr_t) error < (uintptr_t) second_invalid + sizeof(second_invalid),
            "second parser error missing");
    atomicStoreExplicit(&other_parsed, true, memory_order_release);
    while (! atomicLoadExplicit(&start_race, memory_order_acquire))
        YIELD_THREAD();
    parseRepeatedly(second_invalid);
    return 0;
}

int main(void)
{
    testCaseSet("parallel_api_json_parsing");
    require(cJSON_Parse(first_invalid) == NULL, "first invalid JSON parse succeeded");
    const char *expected_error = cJSON_GetErrorPtr();
    wthread_t   thread;
    require(threadCreate(&thread, parseOtherThread, NULL) == kWThreadErrorNone, "parser test thread creation failed");
    while (! atomicLoadExplicit(&other_parsed, memory_order_acquire))
        YIELD_THREAD();
    require(cJSON_GetErrorPtr() == expected_error, "another thread replaced the caller's parser error pointer");
    atomicStoreExplicit(&start_race, true, memory_order_release);
    parseRepeatedly(first_invalid);
    require(threadJoin(thread) == 0, "parser test thread join failed");
    return 0;
}
