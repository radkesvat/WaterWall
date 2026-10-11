/*
 * Covers the real memory_manager.c wrappers with both allocator backends.
 * Backend linker wraps inject NULL below the production failure gate; real
 * backends also refuse impossible SIZE_MAX requests. Child processes must exit
 * with status 1 without atexit cleanup or blocked wrapper diagnostics.
 * Successful cases cover zero sizes, realloc preservation/free, calloc overflow,
 * aligned geometry rejection and zeroed/aligned storage.
 * CTest: waterwall.memory_allocation_unit, waterwall.memory_allocation_bypass_unit
 */
#include "wlibc.h"

#include "test_assert.h"

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

/* Compile the actual implementation in each backend mode after the generated
 * configuration has been included; neither mode needs a production test hook. */
#undef ALLOCATOR_BYPASS
#define ALLOCATOR_BYPASS WW_TEST_ALLOCATOR_BYPASS
#include "../../../ww/managers/memory_manager.c"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_QUICK_EXIT, condition, message)

#if ALLOCATOR_BYPASS
#define REAL_MALLOC  __real_malloc
#define WRAP_MALLOC  __wrap_malloc
#define REAL_CALLOC  __real_calloc
#define WRAP_CALLOC  __wrap_calloc
#define REAL_REALLOC __real_realloc
#define WRAP_REALLOC __wrap_realloc
#define REAL_FREE    __real_free
#define WRAP_FREE    __wrap_free
#else
#define REAL_MALLOC  __real_mi_malloc
#define WRAP_MALLOC  __wrap_mi_malloc
#define REAL_CALLOC  __real_mi_calloc
#define WRAP_CALLOC  __wrap_mi_calloc
#define REAL_REALLOC __real_mi_realloc
#define WRAP_REALLOC __wrap_mi_realloc
#define REAL_FREE    __real_mi_free
#define WRAP_FREE    __wrap_mi_free
#endif

static bool   refuse_allocations;
static size_t allocation_calls;
static void  *tracked_allocation;
static size_t tracked_frees;

void *REAL_MALLOC(size_t size);
void *REAL_CALLOC(size_t n, size_t size);
void *REAL_REALLOC(void *ptr, size_t size);
void  REAL_FREE(void *ptr);
void *WRAP_MALLOC(size_t size);
void *WRAP_CALLOC(size_t n, size_t size);
void *WRAP_REALLOC(void *ptr, size_t size);
void  WRAP_FREE(void *ptr);

void *WRAP_MALLOC(size_t size)
{
    allocation_calls++;
    return refuse_allocations ? NULL : REAL_MALLOC(size);
}

void *WRAP_CALLOC(size_t n, size_t size)
{
    allocation_calls++;
    return refuse_allocations ? NULL : REAL_CALLOC(n, size);
}

void *WRAP_REALLOC(void *ptr, size_t size)
{
    allocation_calls++;
    return refuse_allocations ? NULL : REAL_REALLOC(ptr, size);
}

void WRAP_FREE(void *ptr)
{
    if (ptr != NULL && ptr == tracked_allocation)
        tracked_frees++;
    REAL_FREE(ptr);
}

static void testSuccessfulAllocations(void)
{
    unsigned char *ptr = memoryAllocate(8);
    memset(ptr, 0x5a, 8);
    ptr = memoryReAllocate(ptr, 32);
    for (size_t i = 0; i < 8; ++i)
        require(ptr[i] == 0x5a, "reallocation lost existing bytes");
    memoryFree(ptr);

    ptr = memoryReAllocate(NULL, 8);
    require(ptr != NULL, "reallocation of NULL did not allocate");
    memoryFree(ptr);

    ptr = memoryCalloc(8, 4);
    require(ptr != NULL, "calloc returned NULL for valid geometry");
    for (size_t i = 0; i < 32; ++i)
        require(ptr[i] == 0, "calloc did not clear the allocation");
    memoryFree(ptr);

    ptr = memoryAllocateZero(32);
    for (size_t i = 0; i < 32; ++i)
        require(ptr[i] == 0, "zero allocation did not clear storage");
    memoryFree(ptr);

    ptr = memoryAllocateAlignedZero(33, 64);
    require(ptr != NULL && (uintptr_t) ptr % 64 == 0, "aligned allocation lost its alignment");
    for (size_t i = 0; i < 33; ++i)
        require(ptr[i] == 0, "aligned zero allocation did not clear storage");
    memoryFreeAligned(ptr);
}

static void testZeroAndInvalidGeometry(void)
{
    void *ptr = memoryAllocate(0);
    require(ptr != NULL, "zero malloc must return freeable storage");
    memoryFree(ptr);
    ptr = memoryAllocateZero(0);
    require(ptr != NULL, "zero clear allocation must return freeable storage");
    memoryFree(ptr);
    ptr = memoryAllocateAligned(0, 64);
    require(ptr != NULL && (uintptr_t) ptr % 64 == 0, "zero aligned allocation must provide aligned storage");
    memoryFreeAligned(ptr);

    unsigned char *zero_count = memoryCalloc(0, SIZE_MAX);
    unsigned char *zero_size  = memoryCalloc(SIZE_MAX, 0);
    require(zero_count != NULL && zero_size != NULL && *zero_count == 0 && *zero_size == 0,
            "zero calloc must return a cleared minimum allocation");
    memoryFree(zero_count);
    memoryFree(zero_size);

    tracked_allocation        = memoryAllocate(8);
    const size_t calls_before = allocation_calls;
    require(memoryReAllocate(tracked_allocation, 0) == NULL, "zero realloc must return NULL");
    require(tracked_frees == 1 && allocation_calls == calls_before,
            "zero realloc must free once without calling the allocation backend");
    tracked_allocation = NULL;
    require(memoryReAllocate(NULL, 0) == NULL, "zero realloc of NULL must return NULL");

    const size_t before_invalid = allocation_calls;
    require(memoryCalloc(SIZE_MAX, 2) == NULL, "calloc multiplication overflow was accepted");
    require(memoryCalloc(2, SIZE_MAX) == NULL, "calloc reverse multiplication overflow was accepted");
    require(memoryAllocateAligned(16, 3) == NULL, "non-power-of-two alignment was accepted");
    require(memoryAllocateAligned(16, 0) == NULL, "zero alignment was accepted");
    require(memoryAllocateAligned(SIZE_MAX, 64) == NULL, "aligned allocation size overflow was accepted");
    require(allocation_calls == before_invalid, "invalid geometry reached the allocation backend");
}

static void unexpectedExitCleanup(void)
{
    _Exit(72);
}

static bool blockStandardError(void)
{
    int descriptors[2];
    if (pipe(descriptors) != 0 || fcntl(descriptors[1], F_SETFL, O_NONBLOCK) != 0)
        return false;
    const char byte = 0;
    while (write(descriptors[1], &byte, 1) == 1)
    {
    }
    if (errno != EAGAIN || fcntl(descriptors[1], F_SETFL, 0) != 0 ||
        dup2(descriptors[1], STDERR_FILENO) != STDERR_FILENO)
        return false;
    close(descriptors[1]);
    /* Keep the read end open without consuming data so a diagnostic would block. */
    return true;
}

static void testFatalAllocation(unsigned int kind)
{
    const pid_t child = fork();
    require(child >= 0, "failed to fork allocation failure case");
    if (child == 0)
    {
        void *existing = memoryAllocate(8);
        if (atexit(unexpectedExitCleanup) != 0 || (kind < 9 && ! blockStandardError()))
            _Exit(74);
        alarm(3);
        refuse_allocations              = kind < 9;
        volatile size_t impossible_size = SIZE_MAX;
        switch (kind)
        {
        case 0:
            discard memoryAllocate(8);
            break;
        case 1:
            discard memoryAllocateZero(8);
            break;
        case 2:
            discard memoryCalloc(2, 8);
            break;
        case 3:
            discard memoryReAllocate(existing, 16);
            break;
        case 4:
            discard memoryAllocateAligned(8, 64);
            break;
        case 5:
            discard memoryAllocateAlignedZero(8, 64);
            break;
        case 6:
            discard memoryDedicatedAllocate(NULL, 8);
            break;
        case 7:
            discard memoryAllocate(0);
            break;
        case 8:
            discard memoryCalloc(0, 8);
            break;
        case 9:
            discard memoryAllocate(impossible_size);
            break;
        case 10:
            discard memoryCalloc(1, impossible_size);
            break;
        case 11:
            discard memoryReAllocate(existing, impossible_size);
            break;
        }
        _Exit(73);
    }
    int status = 0;
    require(waitpid(child, &status, 0) == child, "failed to wait for allocation failure case");
    require(WIFEXITED(status) && WEXITSTATUS(status) == 1,
            "allocation failure must exit immediately with status 1, without cleanup or blocked diagnostics");
}

int main(void)
{
    testCaseSet("memory_allocation_test");
    testSuccessfulAllocations();
    testZeroAndInvalidGeometry();
    for (unsigned int kind = 0; kind < 12; ++kind)
        testFatalAllocation(kind);
    puts("memory_allocation_test: all cases passed");
    return 0;
}
