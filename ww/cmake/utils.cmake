include(CheckIncludeFiles)
include(CheckCSourceCompiles)

macro(check_header header)
    string(TOUPPER ${header} str1)
    string(REGEX REPLACE "[/.]" "_" str2 ${str1})
    set(str3 HAVE_${str2})
    check_include_files(${header} ${str3})
    if (${str3})
        set(${str3} 1)
    else()
        set(${str3} 0)
    endif()
endmacro()

macro(check_c11_atomics result)
    check_c_source_compiles([=[
        #include <stdbool.h>
        #include <stdint.h>
        #include <stdatomic.h>

        static atomic_flag       test_flag       = ATOMIC_FLAG_INIT;
        static atomic_bool       test_ready      = ATOMIC_VAR_INIT(false);
        static atomic_uint       test_count      = ATOMIC_VAR_INIT(0U);
        static atomic_ullong     test_generation = ATOMIC_VAR_INIT(0ULL);
        static _Atomic(uintptr_t) test_pointer    = ATOMIC_VAR_INIT((uintptr_t) 0);

        _Static_assert(ATOMIC_INT_LOCK_FREE == 2,
                       "WaterWall requires an always-lock-free atomic_int");

        int main(void)
        {
            bool               expected_ready      = false;
            unsigned long long expected_generation = 0ULL;

            atomic_init(&test_ready, false);
            atomic_store_explicit(&test_pointer, (uintptr_t) 1, memory_order_release);
            (void) atomic_load_explicit(&test_pointer, memory_order_acquire);
            (void) atomic_exchange_explicit(&test_count, 1U, memory_order_acq_rel);
            (void) atomic_fetch_add_explicit(&test_count, 1U, memory_order_relaxed);
            (void) atomic_fetch_sub_explicit(&test_count, 1U, memory_order_relaxed);
            (void) atomic_fetch_or_explicit(&test_count, 1U, memory_order_relaxed);
            (void) atomic_fetch_xor_explicit(&test_count, 1U, memory_order_relaxed);
            (void) atomic_fetch_and_explicit(&test_count, 1U, memory_order_relaxed);
            (void) atomic_compare_exchange_strong_explicit(
                &test_ready, &expected_ready, true, memory_order_acq_rel, memory_order_acquire);
            (void) atomic_compare_exchange_weak_explicit(
                &test_generation, &expected_generation, 1ULL, memory_order_acq_rel, memory_order_acquire);
            (void) atomic_flag_test_and_set_explicit(&test_flag, memory_order_acquire);
            atomic_flag_clear_explicit(&test_flag, memory_order_release);
            atomic_thread_fence(memory_order_seq_cst);
            atomic_signal_fence(memory_order_seq_cst);
            return 0;
        }
    ]=] ${result})

    if(${result})
        set(${result} 1 CACHE INTERNAL "C11 stdatomic is usable by WaterWall" FORCE)
    else()
        set(${result} 0 CACHE INTERNAL "C11 stdatomic is usable by WaterWall" FORCE)
    endif()
endmacro()

include(CheckSymbolExists)
macro(check_function function header)
    string(TOUPPER ${function} str1)
    set(str2 HAVE_${str1})
    check_symbol_exists(${function} ${header} ${str2})
    if (${str2})
        set(${str2} 1)
    else()
        set(${str2} 0)
    endif()
endmacro()

macro(list_source_directories srcs)
    unset(tmp)
    foreach(dir ${ARGN})
        aux_source_directory(${dir} tmp)
    endforeach()
    set(${srcs} ${tmp})
    list(FILTER ${srcs} EXCLUDE REGEX ".*_test\\.c")
endmacro()

macro(glob_headers_and_sources files)
    unset(tmp)
    foreach(dir ${ARGN})
        file(GLOB tmp ${dir}/*.h ${dir}/*.c ${dir}/*.hpp ${dir}/*.cpp)
        list(APPEND ${files} ${tmp})
    endforeach()
    list(FILTER ${files} EXCLUDE REGEX ".*_test\\.c")
endmacro()
