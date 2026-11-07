#pragma once

#include <cstddef>
#include <limits>
#include <memory>
#include <new>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

/* This standalone C++ engine imports only the allocator C ABI. The tunnel's C
 * adapter uses wwapi.h, whose full runtime headers are not C++ compatible. */
extern "C"
{
#include "wmem.h"
    [[noreturn]] void abortProgramNow(int exit_code);
}

/* FEC owns ordinary-aligned objects and containers. Keep their storage at the
 * WaterWall allocation boundary, including shared_ptr control blocks. */
template <class T> struct FecAllocator
{
    using value_type      = T;
    using is_always_equal = std::true_type;

    FecAllocator() noexcept = default;
    template <class U> FecAllocator(const FecAllocator<U> &) noexcept {}

    std::size_t max_size() const noexcept
    {
        return static_cast<std::size_t>(std::numeric_limits<std::ptrdiff_t>::max()) / sizeof(T);
    }

    T *allocate(std::size_t count)
    {
        static_assert(alignof(T) <= alignof(std::max_align_t), "FEC storage requires ordinary alignment");
        if (count > max_size())
            throw std::length_error("FEC allocation size is not representable");
        return static_cast<T *>(memoryAllocate(count * sizeof(T)));
    }

    void deallocate(T *ptr, std::size_t) noexcept { memoryFree(ptr); }
};

template <class T, class U> bool operator==(const FecAllocator<T> &, const FecAllocator<U> &) noexcept
{
    return true;
}

template <class T, class U> bool operator!=(const FecAllocator<T> &, const FecAllocator<U> &) noexcept
{
    return false;
}

template <class T> using FecVector = std::vector<T, FecAllocator<T>>;

template <class T, class... Args> std::shared_ptr<T> fecMakeShared(Args &&...args)
{
    return std::allocate_shared<T>(FecAllocator<T>{}, std::forward<Args>(args)...);
}

template <class T> T *fecCreate()
{
    T *storage = FecAllocator<T>{}.allocate(1);
    try
    {
        return ::new (storage) T;
    }
    catch (const std::bad_alloc &)
    {
        abortProgramNow(1);
    }
    catch (...)
    {
        memoryFree(storage);
        throw;
    }
}

template <class T> void fecDestroy(T *object) noexcept
{
    if (object != nullptr)
    {
        object->~T();
        memoryFree(object);
    }
}
