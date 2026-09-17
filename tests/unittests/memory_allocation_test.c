#include "ev_memory.h"
#include "mimalloc.h"

#if defined(OS_UNIX)
#include <sys/wait.h>
#include <unistd.h>
#endif

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void requireZero(const unsigned char *ptr, size_t size)
{
    require(ptr != NULL, "small allocation failed");
    for (size_t i = 0; i < size; ++i)
    {
        require(ptr[i] == 0, "zero-allocation returned uninitialized bytes");
    }
#if ! ALLOCATOR_BYPASS
    require(mi_check_owned(ptr), "allocation bypassed mimalloc");
#endif
}

static void testRecoverableAllocation(void)
{
    unsigned char *ptr = memoryTryAllocateZero(37);
    requireZero(ptr, 37);
    memorySet(ptr, 0xA5, 37);
    memoryFree(ptr);
    memoryFree(memoryTryAllocateZero(0));

    /* Unrepresentable allocation: exercises the actual backend failure path
     * without exhausting host memory or relying on overcommit behavior. */
    const volatile size_t impossible = (size_t) PTRDIFF_MAX + 1U;
    require(memoryTryAllocateZero(impossible) == NULL, "recoverable allocation did not return NULL");

    const long allocations = eventloopAllocCount();
    const long frees       = eventloopFreeCount();
    require(eventloopTryZalloc(impossible) == NULL, "recoverable event allocation did not return NULL");
    require(eventloopAllocCount() == allocations, "failed event allocation incremented the live allocation count");
    ptr = eventloopTryZalloc(37);
    requireZero(ptr, 37);
    eventloopFree(ptr);
    require(eventloopAllocCount() == allocations + 1 && eventloopFreeCount() == frees + 1,
            "common event release lost allocation accounting");
}

static void testOrdinaryAllocations(void)
{
    unsigned char *ptr = memoryAllocate(37);
    require(ptr != NULL, "ordinary allocation failed");
    memorySet(ptr, 0xA5, 37);
    ptr = memoryReAllocate(ptr, 71);
    require(ptr != NULL, "ordinary reallocation failed");
    for (size_t i = 0; i < 37; ++i)
    {
        require(ptr[i] == 0xA5, "reallocation lost existing bytes");
    }
    memoryFree(ptr);
    ptr = memoryAllocateZero(37);
    requireZero(ptr, 37);
    memoryFree(ptr);
    ptr = memoryCalloc(3, 17);
    requireZero(ptr, 51);
    memoryFree(ptr);
    ptr = eventloopCalloc(3, 17);
    requireZero(ptr, 51);
    eventloopFree(ptr);

    memoryFree(memoryAllocate(0));
    memoryFree(memoryCalloc(0, 17));
    memoryFree(memoryCalloc(17, 0));
    memoryFree(memoryReAllocate(memoryAllocate(37), 0));
    memoryFree(NULL);

    const long outstanding = eventloopAllocCount() - eventloopFreeCount();
    eventloopFree(eventloopMalloc(0));
    eventloopFree(eventloopZalloc(0));
    eventloopFree(eventloopCalloc(0, 17));
    eventloopFree(eventloopRealloc(eventloopMalloc(37), 0, 37));
    require(eventloopAllocCount() - eventloopFreeCount() == outstanding,
            "zero-size event allocation changed outstanding-allocation accounting");
}

#if defined(OS_UNIX)
static void testOrdinaryFailures(void)
{
    for (unsigned int kind = 0; kind < 6; ++kind)
    {
        const pid_t child = fork();
        require(child >= 0, "failed to fork allocation-failure case");
        if (child == 0)
        {
            const volatile size_t impossible     = (size_t) PTRDIFF_MAX + 1U;
            const volatile size_t overflow_count = SIZE_MAX;
            void                 *ptr            = NULL;
            switch (kind)
            {
            case 0:
                ptr = memoryAllocate(impossible);
                break;
            case 1:
                ptr = memoryAllocateZero(impossible);
                break;
            case 2:
                ptr = memoryCalloc(1, impossible);
                break;
            case 3:
                ptr = memoryCalloc(overflow_count, 2);
                break;
            case 4:
                ptr = memoryReAllocate(memoryAllocate(37), impossible);
                break;
            case 5:
                ptr = eventloopCalloc(overflow_count / 2 + 1, 2);
                break;
            }
            memoryFree(ptr);
            _Exit(0);
        }
        int status = 0;
        require(waitpid(child, &status, 0) == child, "failed to wait for allocation-failure case");
        require(WIFEXITED(status) && WEXITSTATUS(status) == 1,
                "ordinary allocation did not terminate through WaterWall's fatal path");
    }
}
#endif

int main(void)
{
    testRecoverableAllocation();
    testOrdinaryAllocations();
#if defined(OS_UNIX)
    testOrdinaryFailures();
#endif
    puts("memory_allocation_test: all cases passed");
    return 0;
}
