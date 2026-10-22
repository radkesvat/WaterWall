/* Runtime-linked global C++ allocator coverage: every replaceable C++17 form,
 * STL storage, throwing constructors, startup/exit, cross-thread release and the
 * fatal heap-exhaustion versus geometry-refusal boundary. The override comes
 * from ww's actual link interface, never from a test-local replacement.
 * CTest: waterwall.cpp_allocation_unit, waterwall.cpp_allocation_bypass_unit. */
#include "mimalloc.h"
#include "test_assert.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

/* Older Clang hides these declarations unless sized deallocation is enabled.
 * The runtime defines every form regardless of delete-expression selection. */
#ifndef __cpp_sized_deallocation
void operator delete(void *ptr, std::size_t size) noexcept;
void operator delete[](void *ptr, std::size_t size) noexcept;
void operator delete(void *ptr, std::size_t size, std::align_val_t alignment) noexcept;
void operator delete[](void *ptr, std::size_t size, std::align_val_t alignment) noexcept;
#endif

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_QUICK_EXIT, condition, message)

namespace
{
std::atomic<size_t> allocations{0}, frees{0}, aligned_allocations{0}, aligned_frees{0};
constexpr auto      alignment = std::align_val_t{256};
bool                main_completed;

void checkBackend(void *ptr)
{
    require(ptr != nullptr, "allocation returned null");
    require(mi_is_in_heap_region(ptr) == ! WW_TEST_ALLOCATOR_BYPASS, "global C++ allocation used the wrong backend");
}
} // namespace

extern "C"
{
    void *__real_memoryAllocate(size_t size);
    void  __real_memoryFree(void *ptr);
    void *__real_memoryAllocateAligned(size_t size, size_t align);
    void  __real_memoryFreeAligned(void *ptr);
    void  memorymanagerInit(void);

    void *__wrap_memoryAllocate(size_t size)
    {
        ++allocations;
        return __real_memoryAllocate(size);
    }
    void __wrap_memoryFree(void *ptr)
    {
        ++frees;
        __real_memoryFree(ptr);
    }
    void *__wrap_memoryAllocateAligned(size_t size, size_t align)
    {
        ++aligned_allocations;
        return __real_memoryAllocateAligned(size, align);
    }
    void __wrap_memoryFreeAligned(void *ptr)
    {
        ++aligned_frees;
        __real_memoryFreeAligned(ptr);
    }
}

namespace
{
template <class Allocate, class Free> void checkPair(Allocate allocate, Free release, bool aligned)
{
    auto &allocation_count = aligned ? aligned_allocations : allocations;
    auto &free_count       = aligned ? aligned_frees : frees;
    for (size_t size : {size_t{0}, sizeof(std::max_align_t)})
    {
        const size_t before_allocate = allocation_count;
        void        *ptr             = allocate(size);
        require(allocation_count == before_allocate + 1, "new bypassed the WaterWall allocator");
        checkBackend(ptr);
        const size_t required_alignment = aligned ? size_t(alignment) : (size == 0 ? 1 : alignof(std::max_align_t));
        require(reinterpret_cast<uintptr_t>(ptr) % required_alignment == 0, "new returned incorrectly aligned storage");
        if (size == 0)
        {
            void *other = allocate(0);
            require(other != nullptr && other != ptr, "live zero-size allocations must have distinct addresses");
            release(other, 0);
        }
        else
        {
            std::memset(ptr, 0x5a, size);
        }
        const size_t before_free = free_count;
        release(ptr, size);
        require(free_count == before_free + 1, "delete did not use the matching WaterWall release");
    }
    release(nullptr, 0);
}

/* This allocation precedes memorymanagerInit(); its release and another
 * allocation run after main. No WaterWall worker or shutdown state exists. */
struct StartupAllocation
{
    void *ptr;
    StartupAllocation() : ptr(::operator new(23))
    {
        checkBackend(ptr);
        require(allocations != 0, "pre-main new bypassed the WaterWall allocator");
    }
    ~StartupAllocation()
    {
        require(main_completed, "main did not finish before global destruction");
        const size_t before_free = frees;
        ::operator delete(ptr);
        require(frees == before_free + 1, "global destructor bypassed the allocator");
        checkPair([](size_t size) { return ::operator new(size); },
                  [](void *value, size_t) { ::operator delete(value); },
                  false);
    }
} startup_allocation;

void testOperatorForms()
{
    auto ordinary = [](size_t size) { return ::operator new(size); };
    auto array    = [](size_t size) { return ::operator new[](size); };
    checkPair(ordinary, [](void *ptr, size_t) { ::operator delete(ptr); }, false);
    checkPair(ordinary, [](void *ptr, size_t size) { ::operator delete(ptr, size); }, false);
    checkPair(array, [](void *ptr, size_t) { ::operator delete[](ptr); }, false);
    checkPair(array, [](void *ptr, size_t size) { ::operator delete[](ptr, size); }, false);
    checkPair([](size_t size) { return ::operator new(size, std::nothrow); },
              [](void *ptr, size_t) { ::operator delete(ptr, std::nothrow); },
              false);
    checkPair([](size_t size) { return ::operator new[](size, std::nothrow); },
              [](void *ptr, size_t) { ::operator delete[](ptr, std::nothrow); },
              false);

    auto aligned       = [](size_t size) { return ::operator new(size, alignment); };
    auto aligned_array = [](size_t size) { return ::operator new[](size, alignment); };
    checkPair(aligned, [](void *ptr, size_t) { ::operator delete(ptr, alignment); }, true);
    checkPair(aligned, [](void *ptr, size_t size) { ::operator delete(ptr, size, alignment); }, true);
    checkPair(aligned_array, [](void *ptr, size_t) { ::operator delete[](ptr, alignment); }, true);
    checkPair(aligned_array, [](void *ptr, size_t size) { ::operator delete[](ptr, size, alignment); }, true);
    checkPair([](size_t size) { return ::operator new(size, alignment, std::nothrow); },
              [](void *ptr, size_t) { ::operator delete(ptr, alignment, std::nothrow); },
              true);
    checkPair([](size_t size) { return ::operator new[](size, alignment, std::nothrow); },
              [](void *ptr, size_t) { ::operator delete[](ptr, alignment, std::nothrow); },
              true);
}

struct Throws
{
    Throws()
    {
        checkBackend(this);
        throw 7;
    }
};
struct alignas(256) AlignedThrows : Throws
{
};

template <class Construct> void checkConstructorFailure(Construct construct, bool aligned)
{
    const size_t before_allocate = aligned ? aligned_allocations.load() : allocations.load();
    const size_t before_free     = aligned ? aligned_frees.load() : frees.load();
    bool         caught          = false;
    try
    {
        construct();
    }
    catch (int value)
    {
        caught = value == 7;
    }
    require(caught, "constructor exception did not reach the caller");
    require((aligned ? aligned_allocations.load() : allocations.load()) == before_allocate + 1,
            "throwing constructor allocation bypassed WaterWall");
    require((aligned ? aligned_frees.load() : frees.load()) == before_free + 1,
            "constructor failure did not release storage exactly once");
}

void testConstructorCleanup()
{
    checkConstructorFailure([] { delete new Throws; }, false);
    checkConstructorFailure([] { delete[] new Throws[2]; }, false);
    checkConstructorFailure([] { delete new (std::nothrow) Throws; }, false);
    checkConstructorFailure([] { delete[] new (std::nothrow) Throws[2]; }, false);
    checkConstructorFailure([] { delete new AlignedThrows; }, true);
    checkConstructorFailure([] { delete[] new AlignedThrows[2]; }, true);
    checkConstructorFailure([] { delete new (std::nothrow) AlignedThrows; }, true);
    checkConstructorFailure([] { delete[] new (std::nothrow) AlignedThrows[2]; }, true);
}

void testContainersAndThreads()
{
    const size_t before = allocations;
    {
        std::vector<uint64_t> values(128, 42);
        checkBackend(values.data());
        require(allocations > before && values.back() == 42, "STL storage bypassed the global allocator");
    }
    void       *worker_allocation = nullptr;
    std::thread worker([&] { worker_allocation = ::operator new(83); });
    worker.join();
    checkBackend(worker_allocation);
    const size_t before_free = frees;
    ::operator delete(worker_allocation);
    require(frees == before_free + 1, "cross-thread release bypassed WaterWall");
}

void testAlignedGeometry()
{
    volatile size_t impossible = std::numeric_limits<size_t>::max();
    require(::operator new(impossible, alignment, std::nothrow) == nullptr,
            "nothrow aligned new accepted overflowing geometry");
    require(::operator new[](impossible, alignment, std::nothrow) == nullptr,
            "nothrow aligned array new accepted overflowing geometry");
    for (bool array : {false, true})
    {
        bool caught = false;
        try
        {
            void *ptr = array ? ::operator new[](impossible, alignment) : ::operator new(impossible, alignment);
            if (array)
            {
                ::operator delete[](ptr, alignment);
            }
            else
            {
                ::operator delete(ptr, alignment);
            }
        }
        catch (const std::bad_alloc &)
        {
            caught = true;
        }
        require(caught, "throwing aligned new did not report overflowing geometry");
    }
}

void unexpectedCleanup()
{
    std::_Exit(72);
}

void testFatalExhaustion()
{
    for (unsigned int kind = 0; kind < 8; ++kind)
    {
        pid_t child = fork();
        require(child >= 0, "could not fork allocation failure case");
        if (child == 0)
        {
            require(std::atexit(unexpectedCleanup) == 0, "could not register unexpected cleanup detector");
            alarm(3);
            /* The aligned size leaves room for allocator bookkeeping, so this
             * tests real heap exhaustion rather than geometry refusal. */
            volatile size_t impossible =
                kind < 4 ? std::numeric_limits<size_t>::max() : std::numeric_limits<size_t>::max() / 2;
            void *ptr;
            switch (kind)
            {
            case 0:
                ptr = ::operator new(impossible);
                break;
            case 1:
                ptr = ::operator new[](impossible);
                break;
            case 2:
                ptr = ::operator new(impossible, std::nothrow);
                break;
            case 3:
                ptr = ::operator new[](impossible, std::nothrow);
                break;
            case 4:
                ptr = ::operator new(impossible, alignment);
                break;
            case 5:
                ptr = ::operator new[](impossible, alignment);
                break;
            case 6:
                ptr = ::operator new(impossible, alignment, std::nothrow);
                break;
            default:
                ptr = ::operator new[](impossible, alignment, std::nothrow);
                break;
            }
            (void) ptr;
            std::_Exit(73);
        }
        int status = 0;
        require(waitpid(child, &status, 0) == child, "could not reap allocation failure case");
        require(WIFEXITED(status) && WEXITSTATUS(status) == 1,
                "heap exhaustion must terminate immediately, including nothrow new");
    }
}
} // namespace

int main()
{
    testCaseSet("cpp_allocation_test");
    testFatalExhaustion();
    memorymanagerInit();
    testOperatorForms();
    testConstructorCleanup();
    testContainersAndThreads();
    testAlignedGeometry();
    main_completed = true;
    std::puts("cpp_allocation_test: all cases passed");
    return 0;
}
