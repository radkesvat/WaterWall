#include <new>

extern "C"
{
#include "wmem.h"
}

/* Keep every replaceable C++ allocation form on the runtime memory boundary.
 * Heap exhaustion is fatal there, including for nothrow new. Aligned geometry
 * refusal is distinct: throwing new reports bad_alloc, nothrow returns null. */
namespace
{
void *allocateAligned(std::size_t size, std::align_val_t alignment)
{
    void *ptr = memoryAllocateAligned(size, static_cast<std::size_t>(alignment));
    if (ptr == nullptr)
    {
        throw std::bad_alloc();
    }
    return ptr;
}
} // namespace

void *operator new(std::size_t size)
{
    return memoryAllocate(size);
}

void *operator new[](std::size_t size)
{
    return memoryAllocate(size);
}

void *operator new(std::size_t size, const std::nothrow_t &) noexcept
{
    return memoryAllocate(size);
}

void *operator new[](std::size_t size, const std::nothrow_t &) noexcept
{
    return memoryAllocate(size);
}

void *operator new(std::size_t size, std::align_val_t alignment)
{
    return allocateAligned(size, alignment);
}

void *operator new[](std::size_t size, std::align_val_t alignment)
{
    return allocateAligned(size, alignment);
}

void *operator new(std::size_t size, std::align_val_t alignment, const std::nothrow_t &) noexcept
{
    return memoryAllocateAligned(size, static_cast<std::size_t>(alignment));
}

void *operator new[](std::size_t size, std::align_val_t alignment, const std::nothrow_t &) noexcept
{
    return memoryAllocateAligned(size, static_cast<std::size_t>(alignment));
}

void operator delete(void *ptr) noexcept
{
    memoryFree(ptr);
}

void operator delete[](void *ptr) noexcept
{
    memoryFree(ptr);
}

void operator delete(void *ptr, std::size_t) noexcept
{
    memoryFree(ptr);
}

void operator delete[](void *ptr, std::size_t) noexcept
{
    memoryFree(ptr);
}

void operator delete(void *ptr, const std::nothrow_t &) noexcept
{
    memoryFree(ptr);
}

void operator delete[](void *ptr, const std::nothrow_t &) noexcept
{
    memoryFree(ptr);
}

void operator delete(void *ptr, std::align_val_t) noexcept
{
    memoryFreeAligned(ptr);
}

void operator delete[](void *ptr, std::align_val_t) noexcept
{
    memoryFreeAligned(ptr);
}

void operator delete(void *ptr, std::size_t, std::align_val_t) noexcept
{
    memoryFreeAligned(ptr);
}

void operator delete[](void *ptr, std::size_t, std::align_val_t) noexcept
{
    memoryFreeAligned(ptr);
}

void operator delete(void *ptr, std::align_val_t, const std::nothrow_t &) noexcept
{
    memoryFreeAligned(ptr);
}

void operator delete[](void *ptr, std::align_val_t, const std::nothrow_t &) noexcept
{
    memoryFreeAligned(ptr);
}
