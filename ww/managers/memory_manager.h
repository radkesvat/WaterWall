/**

Author & Copyright (C) 2017 Johannes Bernhard Steffens.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

-------------------------------------------------------------------------------
*/

/*

    This started from tbman library at https://github.com/johsteffens/tbman/tree/master

    Changed many prats and names of this file, and it is now WW memory manager

    Memory Manager Evaluation: (tested on my machine)

    malloc, free, realloc (stdlib) ...
    speed test alloc-free (general):    457ns per call
    speed test realloc (general)   :   1482ns per call
    speed test alloc-free (local)  :     44ns per call

    tbman_malloc, tbman_free, tbman_realloc ...
    speed test alloc-free (general):    143ns per call
    speed test realloc (general)   :    540ns per call
    speed test alloc-free (local)  :     40ns per call

    tbman_malloc, tbman_nfree, tbman_nrealloc ...
    speed test alloc-free (general):    126ns per call
    speed test realloc (general)   :    418ns per call
    speed test alloc-free (local)  :     32ns per call



*/

#pragma once

// memory manager is not well tested on windows yet...

// #define ALLOCATOR_BYPASS         // switch to stdlib allocators

#include <stddef.h>
#include <stdbool.h>

struct ww_dedictaed_mem_s;

typedef struct ww_dedictaed_mem_s ww_dedictaed_mem_t;

/// Creates a dedicated manager with default parameters
ww_dedictaed_mem_t* wwmDedicatedCreateDefault( void );

/// Creates a dedicated manager with specified parameters (consider using wwmDedicatedCreateDefault)
ww_dedictaed_mem_t* wwmDedicatedCreate
         (
            size_t pool_size,        // size of a memory pool in a token manager
            size_t min_block_size,   // minimal block size
            size_t max_block_size,   // maximal block size
            size_t stepping_method,  // 1: uses power-2 block size stepping; > 1 uses more fine grained stepping
            bool full_align          // true: uses full memory alignment (fastest)
         );

/// Discards a dedicated manager
void wwmDedicatedDiscard( ww_dedictaed_mem_t* o );

/// opens global memory manager (call this once before first usage of global ww_mem functions below)
ww_dedictaed_mem_t* createWWMemoryManager( void );

/// get the memory manager global state
ww_dedictaed_mem_t *getWWMemoryManager(void);

/// set the memory manager global state
void setWWMemoryManager(ww_dedictaed_mem_t *new_state);

/// closes global memory manager (call this once at the end of your program)
void wwmGlobalClose( void );

/// creates a dedicated memory manager instance ( close with wwmDedicatedClose )
static inline ww_dedictaed_mem_t* wwmDedicatedOpen( void ) { return wwmDedicatedCreateDefault(); }

/// closes dedicated  memory manager instance
static inline void wwmDedicatedClose( ww_dedictaed_mem_t* o ) { wwmDedicatedDiscard( o ); }

/**********************************************************************************************************************/
/** Advanced memory management using the internal manager (thread-safe).
 *  This function provides allocation, re-allocation and freeing of memory
 *  with advanced controls to improve memory efficiency.
 *  In this context, a free request is represented as re-allocation with requested_size == 0
 *
 *  Arguments
 *    current_ptr:
 *      Pointer to current memory location:
 *        ==NULL for pure-allocation
 *        !=NULL for re-allocation or freeing
 *
 *    current_size:
 *      Optional information to memory manager about last reserved or requested amount.
 *      Allowed values: 0 or previously requested or reserved amount.
 *                      0 makes the function ignore current_ptr (assumes it is NULL)
 *
 *    requested_size:
 *       > 0 for pure-allocation or re-allocation
 *      == 0 for freeing
 *
 *    granted_size
 *      Memory granted to requester.
 *      The memory manager grants at least the requested amount of bytes. But it may grant more memory.
 *      The requester may use granted memory without re-allocation. (E.g. for dynamic arrays.)
 *      Retrieving the granted amount is optional. Use NULL when not desired.
 *
 *  Return
 *    Allocated memory address. NULL in case all memory was freed.
 *
 *  Alignment: (default behavior)
 *    A request of size of n*m bytes, where n,m are positive integers and m is (largest possible)
 *    integer power of 2, returns an address aligned to the lesser of m and wwmGlobalALIGN
 *    (wwmGlobalALIGN is defined in memory_manager.c).
 *    This provides correct alignment of standard data types but also for composite types
 *    (e.g. int32x4_t) for use with a SIMD extension of the CPU (e.g. Intel's SSE or ARM's Neon).
 *
 */
void* wwmGlobalAlloc(                void* current_ptr,                      size_t requested_size, size_t* granted_size );
void* wwmGlobalNalloc(               void* current_ptr, size_t current_size, size_t requested_size, size_t* granted_size );
void* wwmDedicatedAlloc(  ww_dedictaed_mem_t* o, void* current_ptr,                      size_t requested_size, size_t* granted_size );
void* wwmDedicatedNalloc( ww_dedictaed_mem_t* o, void* current_ptr, size_t current_size, size_t requested_size, size_t* granted_size );

/// malloc, free and realloc (thread-safe).

#ifdef ALLOCATOR_BYPASS
#include <stdlib.h>

static inline void* wwmGlobalMalloc(             size_t size ) { return malloc(size); }
static inline void* wwmGlobalRealloc( void* ptr, size_t size ) { return realloc( ptr,  size ); }
static inline void  wwmGlobalFree(    void* ptr              ) {        free( ptr); }

static inline void* wwmDedicatedMalloc(  ww_dedictaed_mem_t* o,            size_t size ) {(void)o; return malloc(size); }
static inline void* wwmDedicatedRealloc( ww_dedictaed_mem_t* o, void* ptr, size_t size ) {(void)o; return realloc( ptr,  size ); }
static inline void  wwmDedicatedFree(    ww_dedictaed_mem_t* o, void* ptr              ) {(void)o;        free( ptr); }

#else

static inline void* wwmGlobalMalloc(             size_t size ) { return wwmGlobalAlloc( NULL, size, NULL ); }
static inline void* wwmGlobalRealloc( void* ptr, size_t size ) { return wwmGlobalAlloc( ptr,  size, NULL ); }
static inline void  wwmGlobalFree(    void* ptr              ) {        wwmGlobalAlloc( ptr,  0,    NULL ); }

static inline void* wwmDedicatedMalloc(  ww_dedictaed_mem_t* o,            size_t size ) { return wwmDedicatedAlloc( o, NULL, size, NULL ); }
static inline void* wwmDedicatedRealloc( ww_dedictaed_mem_t* o, void* ptr, size_t size ) { return wwmDedicatedAlloc( o, ptr,  size, NULL ); }
static inline void  wwmDedicatedFree(    ww_dedictaed_mem_t* o, void* ptr              ) {        wwmDedicatedAlloc( o, ptr,  0,    NULL ); }


#endif




/// realloc, specifying current size (thread-safe).
static inline void* wwmGlobalNRealloc( void* current_ptr, size_t current_size, size_t new_size )
{
    return wwmGlobalNalloc( current_ptr, current_size, new_size, NULL );
}

static inline void* wwmDedicatedNRealloc( ww_dedictaed_mem_t* o, void* current_ptr, size_t current_size, size_t new_size )
{
    return wwmDedicatedNalloc( o, current_ptr, current_size, new_size, NULL );
}

/// free, specifying current size (thread-safe).
static inline void wwmGlobalNFree( void* current_ptr, size_t current_size )
{
    wwmGlobalNalloc( current_ptr, current_size, 0, NULL );
}

static inline void wwmDedicatedNFree( ww_dedictaed_mem_t* o, void* current_ptr, size_t current_size )
{
    wwmDedicatedNalloc( o, current_ptr, current_size, 0, NULL );
}

/**********************************************************************************************************************/
/// Diagnostics

/// Returns currently granted space for a specified memory instance (thread-safe)
size_t wwmGlobalGrantedSpace(               const void* current_ptr );
size_t wwmDedicatedGrantedSpace( ww_dedictaed_mem_t* o, const void* current_ptr );

/// Returns total of currently granted space (thread-safe)
size_t wwmGlobaltotalGrantedSpace( void );
size_t wwmDedicatedtotalGrantedSpace( ww_dedictaed_mem_t* o );

/// Returns number of open allocation instances (thread-safe)
size_t wwmGlobaltotalInstances( void );
size_t wwmDedicatedtotalInstances( ww_dedictaed_mem_t* o );

/** Iterates through all open instances and calls 'callback' per instance (thread-safe)
 *  The callback function may change the manager's state.
 *  Only instances which where open at the moment of entering 'bcore_wwmDedicatedForEachInstance' are iterated.
 *  While 'bcore_wwmDedicatedForEachInstance' executes, any instance closed or newly opened will not change the iteration.
 */
void wwmGlobalForEachInstance(               void (*cb)( void* arg, void* ptr, size_t space ), void* arg );
void wwmDedicatedForEachInstance( ww_dedictaed_mem_t* o, void (*cb)( void* arg, void* ptr, size_t space ), void* arg );

/// prints internal status to stdout (use only for debugging/testing - not thread-safe)
void printWWMGlobalstatus(               int detail_level );
void printWWMDedicatedstatus( ww_dedictaed_mem_t* o, int detail_level );

/**********************************************************************************************************************/
