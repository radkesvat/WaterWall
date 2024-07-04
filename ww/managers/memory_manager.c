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
*/

/*

    This started from tbman library at https://github.com/johsteffens/tbman/tree/master

    changed many prats and names of this file, and it is now WW memory manager

*/


#include "memory_manager.h"
#include "utils/btree.h"
#include "hmutex.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#ifdef OS_WIN
#include <malloc.h>
#endif
/**********************************************************************************************************************/
// default parameters

static const size_t default_pool_size       = 0x10000;
static const size_t default_min_block_size  = 8;
static const size_t default_max_block_size  = 1024 * 16;
static const size_t default_stepping_method = 1;
static const bool   default_full_align = true;

/// Minimum alignment of memory blocks
#define wwmGlobalALIGN 0x100

/**********************************************************************************************************************/
/// error messages

static void ext_err( const char* func, const char* file, int line, const char* format, ... )
{
    fprintf( stderr, "error in function %s (%s:%i):\n", func, file, line );
    va_list args;
    va_start( args, format );
    vfprintf( stderr, format, args );
    va_end( args );
    fprintf( stderr, "\n" );
    abort();
}

#define ERR( ... ) ext_err( __func__, __FILE__, __LINE__, __VA_ARGS__ )


#define ASSERT_GLOBAL_INITIALIZED() \
 if( wwmGlobalState == NULL ) ERR( "Manager was not initialized. Call createWWMemoryManager() at the beginning of your program." )

/**********************************************************************************************************************/

static inline void* stdlib_alloc( void* current_ptr, size_t requested_size )
{
    if( requested_size == 0 )
    {
        if( current_ptr ) free( current_ptr );
        current_ptr = NULL;
    }
    else
    {
        if( current_ptr )
        {
            current_ptr = realloc( current_ptr, requested_size );
        }
        else
        {
            current_ptr = malloc( requested_size );
        }
        if( !current_ptr ) ERR( "Failed allocating %zu bytes", requested_size );
    }
    return current_ptr;
}

#ifdef OS_UNIX

static inline void* posix_aligned_malloc(size_t alignment, size_t size) {
    void* aligned_memory = NULL;
    int result = posix_memalign(&aligned_memory, alignment, size);
    if (result != 0) {
        return NULL;
    }
    return aligned_memory;
}

#endif

/**********************************************************************************************************************/
/**********************************************************************************************************************/
/** Token-Manager
 *
 *  Fragmentation-free and fast (O(1)) pool based dynamic management using fixed sized blocks.
 *  A free block is identified by a token representing its address. Tokens are managed in a stack.
 *  An alloc-request consumes the top token from stack. A free-request pushes the token back onto the stack.
 *
 *  The instance token_manager_s occupies the memory-pool; being its header. This supports efficient (O(log(n))
 *  determination of the correct token-manager by the memory-manager (s. algorithm below).
 *
 *  Token managers can be run in full-alignment-mode in which they are aligned to pool_size, which is
 *  a power of two. This allows O(1) lookup of the pool manager from any of its managed allocations.
 *
 */
typedef struct token_manager_s
{
    size_t pool_size;
    size_t block_size;
    uint16_t stack_size;  // size of token-stack
    uint16_t stack_index; // index into token-stack

    /** aligned
     *  The memory-pool is considered aligned when the integer-evaluation of its address
     *  is a multiple of pool_size, which means that the pool address can be obtained
     *  from any pointer inside the pool by a mere integer division.
     */
    bool aligned;

    struct block_manager_s* parent;
    size_t parent_index;
    uint16_t token_stack[]; // stack of block-tokens (part of pool)
} token_manager_s;

// ---------------------------------------------------------------------------------------------------------------------

static void token_manager_s_init( token_manager_s* o )
{
    memset( o, 0, sizeof( *o ) );
}

// ---------------------------------------------------------------------------------------------------------------------

static void token_manager_s_down( token_manager_s* o )
{
    (void) o;
}

// ---------------------------------------------------------------------------------------------------------------------

static token_manager_s* token_manager_s_create( size_t pool_size, size_t block_size, bool align )
{
    if( ( pool_size & ( pool_size - 1 ) ) != 0 ) ERR( "pool_size %zu is not a power of two", pool_size );
    size_t stack_size = pool_size / block_size;
    if( stack_size > 0x10000 ) ERR( "stack_size %zu exceeds 0x10000", stack_size );
    size_t reserved_size   = sizeof( token_manager_s ) + sizeof( uint16_t ) * stack_size;
    size_t reserved_blocks = reserved_size / block_size + ( ( reserved_size % block_size ) > 0 );
    if( stack_size < ( reserved_blocks + 1 ) ) ERR( "pool_size %zu is too small", pool_size );

    token_manager_s* o;
    if( align )
    {
#ifdef OS_WIN
        o = _aligned_malloc( pool_size, pool_size );
#elif defined (OS_ANDROID)
        o = posix_aligned_malloc( pool_size, pool_size );
#else
        o = aligned_alloc( pool_size, pool_size );
#endif
        if( !o ) ERR( "Failed aligned allocating %zu bytes", pool_size );
    }
    else
    {
#ifdef OS_WIN
        o = _aligned_malloc( wwmGlobalALIGN, pool_size );
#elif defined (OS_ANDROID)
        o = posix_aligned_malloc( wwmGlobalALIGN, pool_size );
#else
        o = aligned_alloc( wwmGlobalALIGN, pool_size );
#endif
        if( !o ) ERR( "Failed allocating %zu bytes", pool_size );
    }

    token_manager_s_init( o );
    o->aligned = ( ( intptr_t )o & ( intptr_t )( pool_size - 1 ) ) == 0;
    o->pool_size = pool_size;
    o->block_size = block_size;
    o->stack_size = stack_size;
    o->stack_index = 0;
    for( size_t i = 0; i < o->stack_size; i++ ) o->token_stack[ i ] = ( i + reserved_blocks ) < stack_size ? ( i + reserved_blocks ) : 0;
    return o;
}

// ---------------------------------------------------------------------------------------------------------------------

static void token_manager_s_discard( token_manager_s* o )
{
    if( !o ) return;
    token_manager_s_down( o );
#ifdef OS_WIN
    _aligned_free( o );
#else
    free( o );
#endif
}

// ---------------------------------------------------------------------------------------------------------------------

static bool token_manager_s_is_full( token_manager_s* o )
{
    return o->token_stack[ o->stack_index ] == 0;
}

// ---------------------------------------------------------------------------------------------------------------------

static bool token_manager_s_is_empty( token_manager_s* o )
{
    return o->stack_index == 0;
}

// ---------------------------------------------------------------------------------------------------------------------

static void* token_manager_s_alloc( token_manager_s* o )
{
    assert( !token_manager_s_is_full( o ) );
    void* ret = ( uint8_t* )o + o->token_stack[ o->stack_index ] * o->block_size;
    assert( ( uint8_t* )ret >= ( uint8_t* )o + sizeof( token_manager_s ) );
    o->stack_index++;
    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------

// forward declarations (implementation below)
static void block_manager_s_full_to_free( struct block_manager_s* o, token_manager_s* child );
static void block_manager_s_free_to_empty( struct block_manager_s* o, token_manager_s* child );

static void token_manager_s_free( token_manager_s* o, void* ptr )
{
    #ifdef RTCHECKS
        if( o->stack_index == 0 ) ERR( "Block manager is empty." );
        if( ( size_t )( ( ptrdiff_t )( ( uint8_t* )ptr - ( uint8_t* )o ) ) > o->pool_size ) ERR( "Attempt to free memory outside pool." );
    #endif

    uint16_t token = ( ( ptrdiff_t )( ( uint8_t* )ptr - ( uint8_t* )o ) ) / o->block_size;

    #ifdef RTCHECKS
        if( token * o->block_size < sizeof( token_manager_s ) ) ERR( "Attempt to free reserved memory." );
        for( size_t i = o->stack_index; i < o->stack_size; i++ ) if( o->token_stack[ i ] == token ) ERR( "Attempt to free memory that is declared free." );
    #endif // RTCHECKS

    if( o->token_stack[ o->stack_index ] == 0 ) block_manager_s_full_to_free( o->parent, o );

    o->stack_index--;
    o->token_stack[ o->stack_index ] = token;

    if( o->stack_index == 0 ) block_manager_s_free_to_empty( o->parent, o );
}

// ---------------------------------------------------------------------------------------------------------------------

static size_t token_manager_s_total_alloc( const token_manager_s* o )
{
    return o->block_size * o->stack_index;
}

// ---------------------------------------------------------------------------------------------------------------------

static size_t token_manager_s_total_instances( const token_manager_s* o )
{
    return o->stack_index;
}

// ---------------------------------------------------------------------------------------------------------------------

static size_t token_manager_s_total_space( const token_manager_s* o )
{
    return o->pool_size + o->stack_size * sizeof( uint16_t );
}

// ---------------------------------------------------------------------------------------------------------------------

static void token_manager_s_for_each_instance( token_manager_s* o, void (*cb)( void* arg, void* ptr, size_t space ), void* arg )
{
    if( !cb ) return;
    for( size_t i = 0; i < o->stack_index; i++ )
    {
        size_t token = o->token_stack[ i ];
        cb( arg, ( uint8_t* )o + token * o->block_size, o->block_size );
    }
}

// ---------------------------------------------------------------------------------------------------------------------

static void print_token_manager_s_status( const token_manager_s* o, int detail_level )
{
    if( detail_level <= 0 ) return;
    printf( "    pool_size:   %zu\n",  o->pool_size );
    printf( "    block_size:  %zu\n",  o->block_size );
    printf( "    stack_size:  %u\n",   o->stack_size );
    printf( "    aligned:     %s\n",   o->aligned ? "true" : "false" );
    printf( "    stack_index: %zu\n", ( size_t )o->stack_index );
    printf( "    total alloc: %zu\n", token_manager_s_total_alloc( o ) );
    printf( "    total space: %zu\n", token_manager_s_total_space( o ) );
}

// ---------------------------------------------------------------------------------------------------------------------

/**********************************************************************************************************************/
/**********************************************************************************************************************/
/** Block-Manager
 *
 *  Contains an array of token-managers, each of the same block-size.
 *  A token-manager has one of three stats: 'full', 'free' and 'empty'.
 *  A  'full'  token-manager has no space left for allocation
 *  A  'free'  token-manager has (some) space available for allocation.
 *  An 'empty' token-manager has all space available for allocation.
 *  Token managers are linearly arranged by state in the order: full, free, empty.
 *  An index (free_index) points to the full-free border.
 *
 *  Alloc request: O(1)
 *    - redirected to the free_indexe(d) token-manager.
 *    - if that token-manager becomes 'full', free_index is incremented
 *    - if all token-managers are full, a new token-manager is appended at the next alloc request
 *
 *  Free request:
 *    - block_manager_s does not directly receive free requests. Instead the parent-manager directly invokes the
 *      the corresponding token manager.
 *    - If a token-manager turns from full to free, it reports to the block manager, which swaps its position
 *      with the last full token_manager and decrements free_index.
 *    - If a token-manager turns from free to empty, it reports to the block manager, which swaps its position
 *      with the last free token_manager. When enough empty token-managers accumulated (sweep_hysteresis), they
 *      are discarded (memory returned to the system).
 *
 */
typedef struct block_manager_s
{
    size_t pool_size;  // pool size of all token-managers
    size_t block_size; // block size of all token-managers
    bool align;      // attempt to align token_managers to pool_size
    token_manager_s** data;
    size_t size, space;
    size_t free_index;       // entries equal or above free_index have space for allocation
    double sweep_hysteresis; // if ( empty token-managers ) / ( used token-managers ) < sweep_hysteresis, empty token-managers are discarded
    bool aligned;          // all token managers are aligned to pool_size
    struct ww_dedictaed_mem_s* parent;
    btree_vd_s* internal_btree;
} block_manager_s;

// ---------------------------------------------------------------------------------------------------------------------

static void block_manager_s_init( block_manager_s* o )
{
    memset( o, 0, sizeof( *o ) );
    o->aligned = true;
    o->sweep_hysteresis = 0.125;
}

// ---------------------------------------------------------------------------------------------------------------------

static void block_manager_s_down( block_manager_s* o )
{
    if( o->data )
    {
        for( size_t i = 0; i < o->size; i++ ) token_manager_s_discard( o->data[ i ] );
        free( o->data );
        o->data = NULL;
        o->size = o->space = 0;
    }
}

// ---------------------------------------------------------------------------------------------------------------------

static block_manager_s* block_manager_s_create( size_t pool_size, size_t block_size, bool align )
{
    block_manager_s* o = malloc( sizeof( block_manager_s ) );
    if( !o ) ERR( "Failed allocating %zu bytes", sizeof( block_manager_s ) );
    block_manager_s_init( o );
    o->pool_size = pool_size;
    o->block_size = block_size;
    o->align = align;
    return o;
}

// ---------------------------------------------------------------------------------------------------------------------

static void block_manager_s_discard( block_manager_s* o )
{
    if( !o ) return;
    block_manager_s_down( o );
    free( o );
}

// ---------------------------------------------------------------------------------------------------------------------

static void wwmDedicatedlost_alignment( struct ww_dedictaed_mem_s* o, const block_manager_s* child );

static void* block_manager_s_alloc( block_manager_s* o )
{
    if( o->free_index == o->size )
    {
        if( o->size == o->space )
        {
            o->space = ( o->space > 0 ) ? o->space * 2 : 1;

            if( o->data )
            {
                o->data = realloc( o->data, sizeof( token_manager_s* ) * o->space );
            }
            else
            {
                o->data = malloc( sizeof( token_manager_s* ) * o->space );
            }

            if( !o->data ) ERR( "Failed allocating %zu bytes", sizeof( token_manager_s* ) * o->space );
        }
        o->data[ o->size ] = token_manager_s_create( o->pool_size, o->block_size, o->align );
        o->data[ o->size ]->parent_index = o->size;
        o->data[ o->size ]->parent = o;
        if( o->aligned && !o->data[ o->size ]->aligned )
        {
            o->aligned = false;
            wwmDedicatedlost_alignment( o->parent, o );
        }
        if( btree_vd_s_set( o->internal_btree, o->data[ o->size ] ) != 1 ) ERR( "Failed registering block address." );
        o->size++;
    }
    token_manager_s* child = o->data[ o->free_index ];
    void* ret = token_manager_s_alloc( child );
    if( token_manager_s_is_full( child ) ) o->free_index++;
    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------

// A child reports turning full --> free
static void block_manager_s_full_to_free( block_manager_s* o, token_manager_s* child )
{
    assert( o->free_index > 0 );

    o->free_index--;

    // swap child with current free position
    size_t child_index = child->parent_index;
    size_t swapc_index = o->free_index;

    token_manager_s* swapc = o->data[ swapc_index ];
    o->data[ swapc_index ] = child;
    o->data[ child_index ] = swapc;
    child->parent_index = swapc_index;
    swapc->parent_index = child_index;
}

// ---------------------------------------------------------------------------------------------------------------------

static size_t block_manager_s_empty_tail( const block_manager_s* o )
{
    if( o->size == 0 ) return 0;
    size_t empty_index = o->size;
    while( empty_index > 0 && token_manager_s_is_empty( o->data[ empty_index - 1 ] ) ) empty_index--;
    return o->size - empty_index;
}

// ---------------------------------------------------------------------------------------------------------------------

// A child reports turning free --> empty
static void block_manager_s_free_to_empty( block_manager_s* o, token_manager_s* child )
{
    // move empty manager to tail (if not already there)
    size_t child_index = child->parent_index;
    size_t empty_tail  = block_manager_s_empty_tail( o );
    if( empty_tail < o->size )
    {
        size_t swapc_index = o->size - empty_tail - 1;
        if( child_index < swapc_index )
        {
            token_manager_s* swapc = o->data[ swapc_index ];
            o->data[ child_index ] = swapc;
            o->data[ swapc_index ] = child;
            child->parent_index = swapc_index;
            swapc->parent_index = child_index;
            empty_tail++;
        }
    }

    if( empty_tail > ( o->size - empty_tail ) * o->sweep_hysteresis ) // discard empty managers when enough accumulated
    {
        while( o->size > 0 && token_manager_s_is_empty( o->data[ o->size - 1 ] ) )
        {
            o->size--;

            if( btree_vd_s_remove( o->internal_btree, o->data[ o->size ] ) != 1 ) ERR( "Failed removing block address." );

            #ifdef RTCHECKS
                if( btree_vd_s_exists( o->internal_btree, o->data[ o->size ] ) )      ERR( "Removed block address still exists" );
            #endif

            token_manager_s_discard( o->data[ o->size ] );
            o->data[ o->size ] = NULL;
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------

static size_t block_manager_s_total_alloc( const block_manager_s* o )
{
    size_t sum = 0;
    for( size_t i = 0; i < o->size; i++ )
    {
        sum += token_manager_s_total_alloc( o->data[ i ] );
    }
    return sum;
}

// ---------------------------------------------------------------------------------------------------------------------

static size_t block_manager_s_total_instances( const block_manager_s* o )
{
    size_t sum = 0;
    for( size_t i = 0; i < o->size; i++ )
    {
        sum += token_manager_s_total_instances( o->data[ i ] );
    }
    return sum;
}

// ---------------------------------------------------------------------------------------------------------------------

static size_t block_manager_s_total_space( const block_manager_s* o )
{
    size_t sum = 0;
    for( size_t i = 0; i < o->size; i++ )
    {
        sum += token_manager_s_total_space( o->data[ i ] );
    }
    return sum;
}

// ---------------------------------------------------------------------------------------------------------------------

static void block_manager_s_for_each_instance( block_manager_s* o, void (*cb)( void* arg, void* ptr, size_t space ), void* arg )
{
    for( size_t i = 0; i < o->size; i++ ) token_manager_s_for_each_instance( o->data[ i ], cb, arg );
}

// ---------------------------------------------------------------------------------------------------------------------

static void print_block_manager_s_status( const block_manager_s* o, int detail_level )
{
    if( detail_level <= 0 ) return;
    printf( "  pool_size:        %zu\n", o->pool_size );
    printf( "  block_size:       %zu\n", o->block_size );
    printf( "  sweep_hysteresis: %g\n",  o->sweep_hysteresis );
    printf( "  aligned:          %s\n",  o->aligned ? "true" : "false" );
    printf( "  token_managers:   %zu\n", o->size );
    printf( "      full:         %zu\n", o->free_index );
    printf( "      empty:        %zu\n", block_manager_s_empty_tail( o ) );
    printf( "  total alloc:      %zu\n", block_manager_s_total_alloc( o ) );
    printf( "  total space:      %zu\n", block_manager_s_total_space( o ) );
    if( detail_level > 1 )
    {
        for( size_t i = 0; i < o->size; i++ )
        {
            printf( "\nblock manager %zu:\n", i );
            print_token_manager_s_status( o->data[ i ], detail_level - 1 );
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------

/**********************************************************************************************************************/
/**********************************************************************************************************************/
/** Memory-Manager
 *
 *  Contains a fixed-size array of block-managers with exponentially increasing block_size.
 *  (E.g. via size-doubling, but other arrangements are also possible)
 *
 *  Alloc request:
 *     - directed to the block-manager with the smallest fitting bock-size
 *     - if the largest block size is yet too small, the request is passed on to the OS (-->aligned_alloc)
 *       --> O(1) for size requests equal or below largest block size assuming alloc and free requests are statistically
 *           balanced such the overall memory in use is not dramatically varying.
 *
 *  Free request:
 *     - If the previously allocated size is available and all token managers are aligned
 *       the address of the token manager is directly calculated from the allocated address. (O(1))
 *     - Otherwise: The corresponding token-manager is determined via internal_btree from the memory-address
 *       (O(log(n)) - where 'n' is the current amount of token managers.)
 *
 */
typedef struct ww_dedictaed_mem_s
{
    block_manager_s** data; // block managers are sorted by increasing block size
    size_t size;
    size_t pool_size;               // pool size for all token managers
    size_t min_block_size;
    size_t max_block_size;
    bool aligned;                 // all token managers are aligned
    size_t* block_size_array;       // copy of block size values (for fast access)
    btree_vd_s* internal_btree;
    btree_ps_s* external_btree;
    hhybridmutex_t mutex;
} ww_dedictaed_mem_t;

// ---------------------------------------------------------------------------------------------------------------------

void wwmDedicatedinit( ww_dedictaed_mem_t* o, size_t pool_size, size_t min_block_size, size_t max_block_size, size_t stepping_method, bool full_align )
{
    memset( o, 0, sizeof( *o ) );
    hhybridmutex_init(&o->mutex);

    o->internal_btree = btree_vd_s_create( stdlib_alloc );
    o->external_btree = btree_ps_s_create( stdlib_alloc );

    /// The following three values are configurable parameters of memory manager
    o->pool_size      = pool_size;
    o->min_block_size = min_block_size;
    o->max_block_size = max_block_size;

    size_t mask_bxp  = stepping_method;
    size_t size_mask = ( 1 << mask_bxp ) - 1;
    size_t size_inc  = o->min_block_size;
    while( ( size_mask < o->min_block_size ) || ( ( size_mask << 1 ) & o->min_block_size ) != 0 ) size_mask <<= 1;

    size_t space = 0;

    for( size_t block_size = o->min_block_size; block_size <= o->max_block_size; block_size += size_inc )
    {
        if( o->size == space )
        {
            space = space > 0 ? space * 2 : 16;

            if( o->data )
            {
                o->data = realloc( o->data, sizeof( block_manager_s* ) * space );
            }
            else
            {
                o->data = malloc( sizeof( block_manager_s* ) * space );
            }

            if( !o->data ) ERR( "Failed allocating %zu bytes", sizeof( block_manager_s* ) * space );
        }
        o->data[ o->size ] = block_manager_s_create( o->pool_size, block_size, full_align );
        o->data[ o->size ]->internal_btree = o->internal_btree;
        o->data[ o->size ]->parent = o;
        o->size++;

        if( block_size > size_mask )
        {
            size_mask <<= 1;
            size_inc  <<= 1;
        }
    }

    o->block_size_array = malloc( o->size * sizeof( size_t ) );
    if( !o->block_size_array ) ERR( "Failed allocating %zu bytes", o->size * sizeof( size_t ) );

    o->aligned = true;
    for( size_t i = 0; i < o->size; i++ )
    {
        o->aligned = o->aligned && o->data[ i ]->aligned;
        o->block_size_array[ i ] = o->data[ i ]->block_size;
    }
}

// ---------------------------------------------------------------------------------------------------------------------

void wwmDedicateddown( ww_dedictaed_mem_t* o )
{
    size_t leaking_bytes = wwmDedicatedtotalGrantedSpace( o );

    if( leaking_bytes > 0 )
    {
        size_t leaking_instances = wwmDedicatedtotalInstances( o );
        fprintf
        (
            stderr,
            "TBMAN WARNING: Detected %zu instances with a total of %zu bytes leaking space.\n",
            leaking_instances,
            leaking_bytes
        );
    }

    hhybridmutex_lock( &o->mutex );
    if( o->data )
    {
        for( size_t i = 0; i < o->size; i++ ) block_manager_s_discard( o->data[ i ] );
        free( o->data );
    }

    btree_vd_s_discard( o->internal_btree );
    btree_ps_s_discard( o->external_btree );

    if( o->block_size_array ) free( o->block_size_array );

    hhybridmutex_unlock( &o->mutex );
    hhybridmutex_destroy( &o->mutex );
}

// ---------------------------------------------------------------------------------------------------------------------

ww_dedictaed_mem_t* wwmDedicatedCreate
         (
            size_t pool_size,
            size_t min_block_size,
            size_t max_block_size,
            size_t stepping_method,
            bool full_align
         )
{
    ww_dedictaed_mem_t* o = malloc( sizeof( ww_dedictaed_mem_t ) );
    if( !o ) ERR( "Failed allocating %zu bytes", sizeof( ww_dedictaed_mem_t ) );
    wwmDedicatedinit( o, pool_size, min_block_size, max_block_size, stepping_method, full_align );
    return o;
}

// ---------------------------------------------------------------------------------------------------------------------

ww_dedictaed_mem_t* wwmDedicatedCreateDefault( void )
{
#ifdef ALLOCATOR_BYPASS
    return NULL;
#endif
    return wwmDedicatedCreate
    (
        default_pool_size,
        default_min_block_size,
        default_max_block_size,
        default_stepping_method,
        default_full_align
    );
}

// ---------------------------------------------------------------------------------------------------------------------

void wwmDedicatedDiscard( ww_dedictaed_mem_t* o )
{
    if( !o ) return;
    wwmDedicateddown( o );
    free( o );
}

// ---------------------------------------------------------------------------------------------------------------------

static void wwmDedicatedlost_alignment( struct ww_dedictaed_mem_s* o, const block_manager_s* child )
{
    (void) child;
    o->aligned = false;
}

// ---------------------------------------------------------------------------------------------------------------------

static void* wwmDedicatedmem_alloc( ww_dedictaed_mem_t* o, size_t requested_size, size_t* granted_size )
{
    block_manager_s* block_manager = NULL;
    for( size_t i = 0; i < o->size; i++ )
    {
        if( requested_size <= o->block_size_array[ i ] )
        {
            block_manager = o->data[ i ];
            break;
        }
    }

    void* reserved_ptr = NULL;
    if( block_manager )
    {
        reserved_ptr = block_manager_s_alloc( block_manager );
        if( granted_size ) *granted_size = block_manager->block_size;
    }
    else
    {
#ifdef OS_WIN
        reserved_ptr = _aligned_malloc( wwmGlobalALIGN, requested_size );
#elif defined (OS_ANDROID)
        reserved_ptr = posix_aligned_malloc( wwmGlobalALIGN, requested_size );
#else
        reserved_ptr = aligned_alloc( wwmGlobalALIGN, requested_size );
#endif
        if( !reserved_ptr ) ERR( "Failed allocating %zu bytes.", requested_size );
        if( granted_size ) *granted_size = requested_size;
        if( btree_ps_s_set( o->external_btree, reserved_ptr, requested_size ) != 1 ) ERR( "Registering new address failed" );
    }

    return reserved_ptr;
}

// ---------------------------------------------------------------------------------------------------------------------

static void wwmDedicatedmem_free( ww_dedictaed_mem_t* o, void* current_ptr, const size_t* current_size )
{
    if( current_size && *current_size <= o->max_block_size && o->aligned )
    {
        token_manager_s* token_manager = ( token_manager_s* )( ( intptr_t )current_ptr & ~( intptr_t )( o->pool_size - 1 ) );
        token_manager_s_free( token_manager, current_ptr );
    }
    else
    {
        void* block_ptr = btree_vd_s_largest_below_equal( o->internal_btree, current_ptr );
        if( block_ptr && ( ( (uint8_t*)current_ptr - (uint8_t*)block_ptr ) < (long) o->pool_size ) )
        {
            token_manager_s_free( block_ptr, current_ptr );
        }
        else
        {
            if( btree_ps_s_remove( o->external_btree, current_ptr ) != 1 ) ERR( "Attempt to free invalid memory" );
            #ifdef OS_WIN
                _aligned_free( current_ptr );
            #else
                free( current_ptr );
            #endif
            
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------

static void* wwmDedicatedmem_realloc( ww_dedictaed_mem_t* o, void* current_ptr, const size_t* current_size, size_t requested_size, size_t* granted_size )
{
    token_manager_s* token_manager = NULL;
    if( current_size && *current_size <= o->max_block_size && o->aligned )
    {
        token_manager = ( token_manager_s* )( ( intptr_t )current_ptr & ~( intptr_t )( o->pool_size - 1 ) );
    }
    else
    {
        void* block_ptr = btree_vd_s_largest_below_equal( o->internal_btree, current_ptr );
        if( block_ptr && ( ( (uint8_t*)current_ptr - (uint8_t*)block_ptr ) < (long) o->pool_size ) ) token_manager = block_ptr;
    }

    if( token_manager )
    {
        if( requested_size > token_manager->block_size )
        {
            void* reserved_ptr = wwmDedicatedmem_alloc( o, requested_size, granted_size );
            memcpy( reserved_ptr, current_ptr, token_manager->block_size );
            token_manager_s_free( token_manager, current_ptr );
            return reserved_ptr;
        }
        else // size reduction
        {
            block_manager_s* block_manager = NULL;
            for( size_t i = 0; i < o->size; i++ )
            {
                if( requested_size <= o->block_size_array[ i ] )
                {
                    block_manager = o->data[ i ];
                    break;
                }
            }

            if( block_manager->block_size != token_manager->block_size )
            {
                void* reserved_ptr = block_manager_s_alloc( block_manager );
                memcpy( reserved_ptr, current_ptr, requested_size );
                token_manager_s_free( token_manager, current_ptr );
                if( granted_size ) *granted_size = block_manager->block_size;
                return reserved_ptr;
            }
            else
            {
                // same block-size: keep current location
                if( granted_size ) *granted_size = token_manager->block_size;
                return current_ptr;
            }
        }
    }
    else
    {
        if( requested_size <= o->max_block_size ) // new size fits into manager, old size was outside manager
        {
            void* reserved_ptr = wwmDedicatedmem_alloc( o, requested_size, granted_size );
            memcpy( reserved_ptr, current_ptr, requested_size );
            if( btree_ps_s_remove( o->external_btree, current_ptr ) != 1 ) ERR( "Attempt to free invalid memory" );
            #ifdef OS_WIN
                _aligned_free( current_ptr );
            #else
                free( current_ptr );
            #endif
            return reserved_ptr;
        }
        else // neither old nor new size handled by this manager
        {
            size_t* p_current_size = btree_ps_s_val( o->external_btree, current_ptr );
            if( !p_current_size ) ERR( "Could not retrieve current external memory" );
            size_t current_ext_bytes = *p_current_size;

            // is requested bytes is less but not significantly less than current bytes, keep current memory
            if( ( requested_size < current_ext_bytes ) && ( requested_size >= ( current_ext_bytes >> 1 ) ) )
            {
                if( granted_size ) *granted_size = current_ext_bytes;
                return current_ptr;
            }
#ifdef OS_WIN
            void* reserved_ptr = _aligned_malloc( wwmGlobalALIGN, requested_size );
#elif defined (OS_ANDROID)
            void* reserved_ptr = posix_aligned_malloc( wwmGlobalALIGN, requested_size );
#else
            void* reserved_ptr = aligned_alloc( wwmGlobalALIGN, requested_size );
#endif
            if( !reserved_ptr ) ERR( "Failed allocating %zu bytes.", requested_size );
            if( granted_size ) *granted_size = requested_size;
            if( btree_ps_s_set( o->external_btree, reserved_ptr, requested_size ) != 1 ) ERR( "Registering new address failed" );

            size_t copy_bytes = ( requested_size < current_ext_bytes ) ? requested_size : current_ext_bytes;
            memcpy( reserved_ptr, current_ptr, copy_bytes );

            if( btree_ps_s_remove( o->external_btree, current_ptr ) != 1 ) ERR( "Attempt to free invalid memory" );
            #ifdef OS_WIN
                _aligned_free( current_ptr );
            #else
                free( current_ptr );
            #endif
            return reserved_ptr;
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------

void* wwmDedicatedAlloc( ww_dedictaed_mem_t* o, void* current_ptr, size_t requested_size, size_t* granted_size )
{
    hhybridmutex_lock( &o->mutex );
    void* ret = NULL;
    if( requested_size == 0 )
    {
        if( current_ptr )
        {
            wwmDedicatedmem_free( o, current_ptr, NULL );
        }
        if( granted_size ) *granted_size = 0;
    }
    else
    {
        if( current_ptr )
        {
            ret = wwmDedicatedmem_realloc( o, current_ptr, NULL, requested_size, granted_size );
        }
        else
        {
            ret = wwmDedicatedmem_alloc( o, requested_size, granted_size );
        }
    }
    hhybridmutex_unlock( &o->mutex );
    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------

void* wwmDedicatedNalloc( ww_dedictaed_mem_t* o, void* current_ptr, size_t current_size, size_t requested_size, size_t* granted_size )
{
    hhybridmutex_lock( &o->mutex );
    void* ret = NULL;
    if( requested_size == 0 )
    {
        if( current_size ) // 0 means current_ptr may not be used for free or realloc
        {
            wwmDedicatedmem_free( o, current_ptr, &current_size );
        }
        if( granted_size ) *granted_size = 0;
    }
    else
    {
        if( current_size ) // 0 means current_ptr may not be used for free or realloc
        {
            ret = wwmDedicatedmem_realloc( o, current_ptr, &current_size, requested_size, granted_size );
        }
        else
        {
            ret = wwmDedicatedmem_alloc( o, requested_size, granted_size );
        }
    }
    hhybridmutex_unlock( &o->mutex );
    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------

static size_t wwmDedicatedexternal_total_alloc( const ww_dedictaed_mem_t* o )
{
    return btree_ps_s_sum( o->external_btree, NULL, NULL );
}

// ---------------------------------------------------------------------------------------------------------------------

static void ext_count( void* arg, btree_ps_key_t key, btree_ps_val_t val ) { 
    (void) key;
    (void) val;
    *(size_t*)arg += 1; 
    
}

static size_t wwmDedicatedexternal_total_instances( const ww_dedictaed_mem_t* o )
{
    size_t size = 0;
    btree_ps_s_run( o->external_btree, ext_count, &size );
    return size;
}

// ---------------------------------------------------------------------------------------------------------------------

typedef struct ext_for_instance_arg
{
    void (*cb)( void* arg, void* ptr, size_t space );
    void* arg;
} ext_for_instance_arg;

static void ext_for_instance( void* arg, btree_ps_key_t key, btree_ps_val_t val )
{
    ext_for_instance_arg* iarg = arg;
    iarg->cb( iarg->arg, key, val );
}

static void wwmDedicatedexternal_for_each_instance( ww_dedictaed_mem_t* o, void (*cb)( void* arg, void* ptr, size_t space ), void* arg )
{
    ext_for_instance_arg iarg = { .cb = cb, .arg = arg };
    btree_ps_s_run( o->external_btree, ext_for_instance, &iarg );
}

// ---------------------------------------------------------------------------------------------------------------------

static size_t wwmDedicatedinternal_total_alloc( const ww_dedictaed_mem_t* o )
{
    size_t sum = 0;
    for( size_t i = 0; i < o->size; i++ )
    {
        sum += block_manager_s_total_alloc( o->data[ i ] );
    }
    return sum;
}

// ---------------------------------------------------------------------------------------------------------------------

static size_t wwmDedicatedinternal_total_instances( const ww_dedictaed_mem_t* o )
{
    size_t sum = 0;
    for( size_t i = 0; i < o->size; i++ )
    {
        sum += block_manager_s_total_instances( o->data[ i ] );
    }
    return sum;
}

// ---------------------------------------------------------------------------------------------------------------------

static void wwmDedicatedinternal_for_each_instance( ww_dedictaed_mem_t* o, void (*cb)( void* arg, void* ptr, size_t space ), void* arg )
{
    for( size_t i = 0; i < o->size; i++ )
    {
        block_manager_s_for_each_instance( o->data[ i ], cb, arg );
    }
}

// ---------------------------------------------------------------------------------------------------------------------

static size_t wwmDedicatedtotal_alloc( const ww_dedictaed_mem_t* o )
{
    return wwmDedicatedexternal_total_alloc( o )
         + wwmDedicatedinternal_total_alloc( o );
}

// ---------------------------------------------------------------------------------------------------------------------

static size_t wwmDedicatedtotal_space( const ww_dedictaed_mem_t* o )
{
    size_t sum = 0;
    for( size_t i = 0; i < o->size; i++ )
    {
        sum += block_manager_s_total_space( o->data[ i ] );
    }
    return sum;
}

// ---------------------------------------------------------------------------------------------------------------------

/**********************************************************************************************************************/
// Interface

static ww_dedictaed_mem_t* wwmGlobalState = NULL;

// ---------------------------------------------------------------------------------------------------------------------

static void createWWGlobalMemory(void)
{
    wwmGlobalState = wwmDedicatedCreate
    (
        default_pool_size,
        default_min_block_size,
        default_max_block_size,
        default_stepping_method,
        default_full_align
    );
}

// ---------------------------------------------------------------------------------------------------------------------

static void discard_tbman(void)
{
    wwmDedicatedDiscard( wwmGlobalState );
    wwmGlobalState = NULL;
}

// ---------------------------------------------------------------------------------------------------------------------

ww_dedictaed_mem_t* createWWMemoryManager( void )
{
#ifdef ALLOCATOR_BYPASS
    return NULL;
#endif
    assert(wwmGlobalState == NULL);
    static honce_t flag = HONCE_INIT;
    honce( &flag, createWWGlobalMemory );
    return wwmGlobalState;
}

ww_dedictaed_mem_t *getWWMemoryManager(void)
{
    return wwmGlobalState;
}

void setWWMemoryManager(ww_dedictaed_mem_t *new_state)
{
    assert(wwmGlobalState == NULL);
    wwmGlobalState = new_state;
}

// ---------------------------------------------------------------------------------------------------------------------

void wwmGlobalClose( void )
{
    discard_tbman();
}

// ---------------------------------------------------------------------------------------------------------------------

void* wwmGlobalAlloc( void* current_ptr, size_t requested_size, size_t* granted_size )
{
    ASSERT_GLOBAL_INITIALIZED();
    return wwmDedicatedAlloc( wwmGlobalState, current_ptr, requested_size, granted_size );
}

// ---------------------------------------------------------------------------------------------------------------------

void* wwmGlobalNalloc( void* current_ptr, size_t current_size, size_t requested_size, size_t* granted_size )
{
    ASSERT_GLOBAL_INITIALIZED();
    return wwmDedicatedNalloc( wwmGlobalState, current_ptr, current_size, requested_size, granted_size );
}

// ---------------------------------------------------------------------------------------------------------------------

size_t wwmGlobalStaterantedSpace( ww_dedictaed_mem_t* o, const void* current_ptr )
{
    token_manager_s* token_manager = NULL;
    {
        void* block_ptr = btree_vd_s_largest_below_equal( o->internal_btree, ( void* )current_ptr );
        if( block_ptr && ( ( ( uint8_t* )current_ptr - ( uint8_t* )block_ptr ) < (long) o->pool_size ) ) token_manager = block_ptr;
    }

    if( token_manager )
    {
        return token_manager->block_size;
    }
    else
    {
        size_t* p_current_size = btree_ps_s_val( o->external_btree, ( void* )current_ptr );
        if( !p_current_size ) return 0;
        return *p_current_size;
    }
}

// ---------------------------------------------------------------------------------------------------------------------

size_t wwmGlobalGrantedSpace( const void* current_ptr )
{
    ASSERT_GLOBAL_INITIALIZED();
    return wwmGlobalStaterantedSpace( wwmGlobalState, current_ptr );
}

// ---------------------------------------------------------------------------------------------------------------------

size_t wwmDedicatedtotalGrantedSpace( ww_dedictaed_mem_t* o )
{
    hhybridmutex_lock( &o->mutex );
    size_t space = wwmDedicatedtotal_alloc( o );
    hhybridmutex_unlock( &o->mutex );
    return space;
}

// ---------------------------------------------------------------------------------------------------------------------

size_t wwmGlobaltotalGrantedSpace( void )
{
    ASSERT_GLOBAL_INITIALIZED();
    return wwmDedicatedtotalGrantedSpace( wwmGlobalState );
}

// ---------------------------------------------------------------------------------------------------------------------

size_t wwmGlobaltotalInstances( void )
{
    ASSERT_GLOBAL_INITIALIZED();
    return wwmDedicatedtotalInstances( wwmGlobalState );
}

// ---------------------------------------------------------------------------------------------------------------------

size_t wwmDedicatedtotalInstances( ww_dedictaed_mem_t* o )
{
    hhybridmutex_lock( &o->mutex );
    size_t count = 0;
    count += wwmDedicatedexternal_total_instances( o );
    count += wwmDedicatedinternal_total_instances( o );
    hhybridmutex_unlock( &o->mutex );
    return count;
}

// ---------------------------------------------------------------------------------------------------------------------

typedef struct wwmGlobalmnode { void* p; size_t s; } wwmGlobalmnode;
typedef struct wwmGlobalmnode_arr { wwmGlobalmnode* data; size_t size; size_t space; } wwmGlobalmnode_arr;

static void for_each_instance_collect_callback( void* arg, void* ptr, size_t space )
{
    assert( arg );
    wwmGlobalmnode_arr* arr = arg;
    assert( arr->size < arr->space );
    arr->data[ arr->size ] = ( wwmGlobalmnode ){ .p = ptr, .s = space };
    arr->size++;
}

void wwmDedicatedForEachInstance( ww_dedictaed_mem_t* o, void (*cb)( void* arg, void* ptr, size_t space ), void* arg )
{
    if( !cb ) return;
    size_t size = wwmDedicatedtotalInstances( o );
    if( !size ) return;

    wwmGlobalmnode_arr arr;
    arr.data  = malloc( sizeof( wwmGlobalmnode ) * size );
    arr.space = size;
    arr.size  = 0;

    hhybridmutex_lock( &o->mutex );
    wwmDedicatedexternal_for_each_instance( o, for_each_instance_collect_callback, &arr );
    wwmDedicatedinternal_for_each_instance( o, for_each_instance_collect_callback, &arr );
    hhybridmutex_unlock( &o->mutex );

    assert( arr.size == arr.space );

    for( size_t i = 0; i < size; i++ ) cb( arg, arr.data[ i ].p, arr.data[ i ].s );

    free( arr.data );
}

// ---------------------------------------------------------------------------------------------------------------------

void wwmGlobalForEachInstance( void (*cb)( void* arg, void* ptr, size_t space ), void* arg )
{
    ASSERT_GLOBAL_INITIALIZED();
    wwmDedicatedForEachInstance( wwmGlobalState, cb, arg );
}

// ---------------------------------------------------------------------------------------------------------------------

// not thread-safe
void printWWMDedicatedstatus( ww_dedictaed_mem_t* o, int detail_level )
{
    if( detail_level <= 0 ) return;
    printf( "pool_size:              %zu\n", o->pool_size );
    printf( "block managers:         %zu\n", o->size );
    printf( "token managers:         %zu\n", btree_vd_s_count( o->internal_btree, NULL, NULL ) );
    printf( "external allocs:        %zu\n", btree_ps_s_count( o->external_btree, NULL, NULL ) );
    printf( "internal_btree depth:   %zu\n", btree_vd_s_depth( o->internal_btree ) );
    printf( "external_btree depth:   %zu\n", btree_ps_s_depth( o->external_btree ) );
    printf( "min_block_size:         %zu\n", o->size > 0 ? o->data[ 0 ]->block_size : 0 );
    printf( "max_block_size:         %zu\n", o->size > 0 ? o->data[ o->size - 1 ]->block_size : 0 );
    printf( "aligned:                %s\n",  o->aligned ? "true" : "false" );
    printf( "total external granted: %zu\n", wwmDedicatedexternal_total_alloc( o ) );
    printf( "total internal granted: %zu\n", wwmDedicatedinternal_total_alloc( o ) );
    printf( "total internal used:    %zu\n", wwmDedicatedtotal_space( o ) );
    if( detail_level > 1 )
    {
        for( size_t i = 0; i < o->size; i++ )
        {
            printf( "\nblock manager %zu:\n", i );
            print_block_manager_s_status( o->data[ i ], detail_level - 1 );
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------

void printWWMGlobalstatus( int detail_level )
{
    printWWMDedicatedstatus( wwmGlobalState, detail_level );
}

/**********************************************************************************************************************/
