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

/** Test and evaluation program for a memory manager.
 *  This application realistically simulates memory-intensive usage of
 *  memory management, monitoring data integrity and processing speed.
 *  It compares tbman with stdlib's memory manager.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <math.h>
#include <time.h>

#include "tbman.h"

// ---------------------------------------------------------------------------------------------------------------------
/// Error messages

void eval_wrnv( const char* format, va_list args )
{
    vfprintf( stderr, format, args );
    fprintf( stderr, "\n" );
}

void eval_err( const char* format, ... )
{
    va_list args;
    va_start( args, format );
    eval_wrnv( format, args );
    va_end( args );
    abort();
}

/// same purpose as assert() but cannot be switched off via NDEBUG; typically used in selftests
#define ASSERT( condition ) if( !(condition) ) eval_err( "assertion '%s' failed in function %s (%s line %i)\n", #condition, __func__, __FILE__, __LINE__ )

// ---------------------------------------------------------------------------------------------------------------------

/// function pointer to generalized alloc function
typedef void* (*fp_alloc)( void* current_ptr, size_t current_bytes, size_t requested_bytes, size_t* granted_bytes );

// ---------------------------------------------------------------------------------------------------------------------

/** Xor Shift Generator.
 *  The random generator below belongs to the family of xorshift generators
 *  discovered by George Marsaglia (http://www.jstatsoft.org/v08/i14/paper).
 *  At approximately 50% higher CPU effort, these generators exhibit
 *  significantly better randomness than typical linear congruential
 *  generators.
 *
 *  (Not suitable for cryptographic purposes)
 */
static inline uint32_t xsg_u2( uint32_t rval )
{
    rval ^= ( rval >>  7 );
    rval ^= ( rval << 25 );
    return rval ^ ( rval >> 12 );
}

// ---------------------------------------------------------------------------------------------------------------------

/** Rigorous Monte Carlo based Memory Manager Test.
 *
 *  This routine evaluates the integrity and speed of a chosen memory
 *  management (MM) system by randomly allocating, reallocating and
 *  freeing memory within a contingent of memory instances using randomized
 *  size distribution.
 *
 *  For speed measurements we simulate realistic conditions by choosing a
 *  Zipfian distribution of instance-size and by keeping the total memory at
 *  equilibrium.
 *  Thus, malloc & free need to be tested in combination but realloc can be
 *  tested in isolation.
 *
 *  In tests labeled 'general' a vast amount of arbitrary instances are
 *  processed. In tests labeled 'local', few instances get repeatedly allocated
 *  and free-d. In local tests we can expect MM's relevant metadata
 *  to remain in cache. Thus, the local test better reflect MM's algorithmic
 *  overhead and is most representative for routines with high computational
 *  but little memory complexity.
 *
 *  Time values are given in approximate averaged nanoseconds (ns) needed
 *  executing a single call (malloc, free or realloc).
 *
 *  Note that apart form the MM's algorithms used, speed measurements are also
 *  highly sensitive to platform specifications such as
 *    - CPU speed
 *    - Type and speed of memory
 *    - Type and amount of cache
 *    - The distribution of free system memory
 *      (--> makes results fluctuate)
 *
 *  Hence, we recommend to run tests repeatedly and to consider testing
 *  different platforms in order to obtain an adequate picture of the MM's
 *  ability.
 */
void alloc_challenge
     (
         fp_alloc alloc,
         size_t table_size,
         size_t cycles,
         size_t max_alloc,
         uint32_t seed,
         bool cleanup,
         bool verbose
     )
{
    void**   data_table = malloc( table_size * sizeof( void* ) );
    size_t*  size_table = malloc( table_size * sizeof( size_t ) );
    for( size_t i = 0; i < table_size; i++ ) data_table[ i ] = NULL;
    for( size_t i = 0; i < table_size; i++ ) size_table[ i ] = 0;

    uint32_t rval = seed;
    size_t alloc_attempts = 0;
    size_t realloc_attempts = 0;
    size_t free_attempts = 0;
    size_t alloc_failures = 0;
    size_t realloc_failures = 0;
    size_t free_failures = 0;

    // Functionality test: Mix of malloc, free, realloc
    for( size_t j = 0; j < cycles; j++ )
    {
        for( size_t i = 0; i < table_size; i++ )
        {
            rval = xsg_u2( rval );
            size_t idx = rval % table_size;

            // verify table content
            if( size_table[ idx ] > 0 )
            {
                uint32_t rv = xsg_u2( idx + 1 );
                uint8_t* data = data_table[ idx ];
                size_t sz = size_table[ idx ];
                for( size_t i = 0; i < sz; i++ )
                {
                    rv = xsg_u2( rv );
                    if( data[ i ] != ( rv & 255 ) )
                    {
                        fprintf( stderr, "data failure [%u vs %u].", ( uint32_t )data[ i ], ( uint32_t )( rv & 255 ) );
                        abort();
                    }
                }
            }

            if( data_table[ idx ] == NULL )
            {
                rval = xsg_u2( rval );
                size_t size = pow( ( double )max_alloc, ( rval * pow( 2.0, -32 ) ) );
                data_table[ idx ] = alloc( data_table[ idx ], 0, size, &size_table[ idx ] );
                alloc_attempts++;
                alloc_failures += ( size > 0 ) && ( data_table[ idx ] == NULL );

                // set new content
                if( size_table[ idx ] > 0 )
                {
                    uint32_t rv = xsg_u2( idx + 1 );
                    uint8_t* data = data_table[ idx ];
                    size_t sz = size_table[ idx ];
                    for( size_t i = 0; i < sz; i++ ) data[ i ] = ( ( rv = xsg_u2( rv ) ) & 255 );
                }
            }
            else
            {
                rval = xsg_u2( rval );
                if( rval & 32 )
                {
                    data_table[ idx ] = alloc( data_table[ idx ], size_table[ idx ], 0, &size_table[ idx ] ); // free
                    free_attempts++;
                    free_failures += ( data_table[ idx ] != NULL );
                }
                else
                {
                    rval = xsg_u2( rval );
                    size_t size = pow( ( double )max_alloc, rval * pow( 2.0, -32 ) );

                    size_t new_size = 0;

                    data_table[ idx ] = alloc( data_table[ idx ], size_table[ idx ], size, &new_size ); // realloc

                    // verify old table content (only when size > sz - stdlib realloc does not seem to retain data otherwise)
                    if( size > size_table[ idx ] )
                    {
                        if( data_table[ idx ] != NULL && size_table[ idx ] > 0 )
                        {
                            uint32_t rv = xsg_u2( idx + 1 );
                            uint8_t* data = data_table[ idx ];
                            size_t sz = size_table[ idx ];
                            for( size_t i = 0; i < sz; i++ )
                            {
                                rv = xsg_u2( rv );
                                if( data[ i ] != ( rv & 255 ) )
                                {
                                    fprintf( stderr, "data failure [%u vs %u].", ( uint32_t )data[ i ], ( uint32_t )( rv & 255 ) );
                                    abort();
                                }
                            }
                        }
                    }

                    size_table[ idx ] = new_size; //( data_table[ idx ] != NULL ) ? size : 0;
                    realloc_attempts++;
                    realloc_failures += ( size > 0 ) && ( data_table[ idx ] == NULL );

                    // set new content
                    if( size_table[ idx ] > 0 )
                    {
                        uint32_t rv = xsg_u2( idx + 1 );
                        uint8_t* data = data_table[ idx ];
                        size_t sz = size_table[ idx ];
                        for( size_t i = 0; i < sz; i++ ) data[ i ] = ( ( rv = xsg_u2( rv ) ) & 255 );
                    }
                }
            }
        }
    }

    size_t allocated_table_size = 0;
    for( size_t i = 0; i < table_size; i++ ) allocated_table_size += ( data_table[ i ] != NULL );

    if( verbose )
    {
        printf( "cycles ............... %zu\n", cycles );
        printf( "max alloc size ....... %zu\n", max_alloc );
        printf( "Instances\n" );
        printf( "  total .............. %zu\n", table_size );
        printf( "  allocated .......... %zu\n", allocated_table_size );
        printf( "Alloc\n" );
        printf( "  attempts  .......... %zu\n", alloc_attempts );
        printf( "  failures  .......... %zu\n", alloc_failures );
        printf( "Realloc\n" );
        printf( "  attempts  .......... %zu\n", realloc_attempts );
        printf( "  failures  .......... %zu\n", realloc_failures );
        printf( "Free\n" );
        printf( "  attempts  .......... %zu\n", free_attempts );
        printf( "  failures  .......... %zu\n", free_failures );
    }

    size_t local_table_size = 10 < table_size ? 10 : table_size;
    size_t local_cycles     = table_size / local_table_size;

    // Dummy loops: Assessment of overhead time, which is to be
    // subtracted from time needed for the principal loop
    clock_t overhead_time = 0;
    {
        size_t* size_buf = malloc( table_size * sizeof( size_t ) );
        clock_t time = clock();
        for( size_t j = 0; j < cycles; j++ )
        {
            for( size_t i = 0; i < table_size; i++ )
            {
                rval = xsg_u2( rval );
                size_t idx = rval % table_size;
                rval = xsg_u2( rval );
                size_t size = pow( ( double )max_alloc, rval * pow( 2.0, -32 ) );
                if( data_table[ idx ] == NULL )
                {
                    size_buf[ idx ] = size;
                }
                else
                {
                    size_buf[ idx ] = 0;
                }
            }
        }
        free( size_buf );
        overhead_time = clock() - time;
    }

    clock_t local_overhead_time = 0;
    {
        size_t* size_buf = malloc( table_size * sizeof( size_t ) );
        clock_t time = clock();
        for( size_t k = 0; k < cycles; k++ )
        {
            size_t local_seed = ( rval = xsg_u2( rval ) );
            for( size_t j = 0; j < local_cycles; j++ )
            {
                rval = local_seed;
                for( size_t i = 0; i < local_table_size; i++ )
                {
                    rval = xsg_u2( rval );
                    size_t idx = rval % table_size;
                    rval = xsg_u2( rval );
                    size_t size = pow( ( double )max_alloc, rval * pow( 2.0, -32 ) );
                    if( data_table[ idx ] == NULL )
                    {
                        size_buf[ idx ] = size;
                    }
                    else
                    {
                        size_buf[ idx ] = 0;
                    }
                }
            }
        }
        free( size_buf );
        local_overhead_time = clock() - time;
    }

    // Equilibrium speed test: malloc, free
    {
        clock_t time = clock();
        for( size_t j = 0; j < cycles; j++ )
        {
            for( size_t i = 0; i < table_size; i++ )
            {
                rval = xsg_u2( rval );
                size_t idx = rval % table_size;
                rval = xsg_u2( rval );
                size_t size = pow( ( double )max_alloc, rval * pow( 2.0, -32 ) );
                if( data_table[ idx ] == NULL )
                {
                    data_table[ idx ] = alloc( data_table[ idx ], 0, size, &size_table[ idx ] ); // malloc
                }
                else
                {
                    data_table[ idx ] = alloc( data_table[ idx ], size_table[ idx ], 0, &size_table[ idx ] ); // free
                }
            }
        }
        time = clock() - time - overhead_time;
        size_t ns = ( 1E9 * time ) / ( CLOCKS_PER_SEC  * cycles  * table_size );
        printf( "speed test alloc-free (general): %6zuns per call\n", ns );
    }

    // Equilibrium speed test: realloc
    {
        clock_t time = clock();
        for( size_t j = 0; j < cycles; j++ )
        {
            for( size_t i = 0; i < table_size; i++ )
            {
                rval = xsg_u2( rval );
                size_t idx = rval % table_size;
                rval = xsg_u2( rval );
                size_t size = pow( ( double )max_alloc, rval * pow( 2.0, -32 ) );
                data_table[ idx ] = alloc( data_table[ idx ], size_table[ idx ], size, &size_table[ idx ] ); // realloc
            }
        }
        time = clock() - time - overhead_time;
        size_t ns = ( 1E9 * time ) / ( CLOCKS_PER_SEC  * cycles  * table_size );
        printf( "speed test realloc (general)   : %6zuns per call\n", ns );
    }

    // Local speed test: malloc, free
    {
        clock_t time = clock();
        for( size_t k = 0; k < cycles; k++ )
        {
            size_t local_seed = ( rval = xsg_u2( rval ) );
            for( size_t j = 0; j < local_cycles; j++ )
            {
                rval = local_seed;
                for( size_t i = 0; i < local_table_size; i++ )
                {
                    rval = xsg_u2( rval );
                    size_t idx = rval % table_size;
                    rval = xsg_u2( rval );
                    size_t size = pow( ( double )max_alloc, rval * pow( 2.0, -32 ) );
                    if( data_table[ idx ] == NULL )
                    {
                        data_table[ idx ] = alloc( data_table[ idx ], 0, size, &size_table[ idx ] ); // malloc
                    }
                    else
                    {
                        data_table[ idx ] = alloc( data_table[ idx ], size_table[ idx ], 0, &size_table[ idx ] ); // free
                    }
                }
            }
        }
        time = clock() - time - local_overhead_time;
        size_t total_cycles = cycles * local_cycles  * local_table_size;
        size_t ns = ( 1E9 * time ) / ( CLOCKS_PER_SEC  * total_cycles );
        printf( "speed test alloc-free (local)  : %6zuns per call\n", ns );
    }

    // cleanup
    if( cleanup ) for( size_t i = 0; i < table_size; i++ ) data_table[ i ] = alloc( data_table[ i ], size_table[ i ], 0, NULL );

    free( size_table );
    free( data_table );
}

// ---------------------------------------------------------------------------------------------------------------------

// generalized alloc function purely based on stdlib
static inline void* external_alloc( void* current_ptr, size_t requested_bytes, size_t* granted_bytes )
{
    if( requested_bytes == 0 )
    {
        if( current_ptr ) free( current_ptr );
        current_ptr = NULL;
        if( granted_bytes ) *granted_bytes = 0;
    }
    else
    {
        if( current_ptr )
        {
            current_ptr = realloc( current_ptr, requested_bytes );
        }
        else
        {
            current_ptr = malloc( requested_bytes );
        }
        if( !current_ptr )
        {
            fprintf( stderr, "Failed allocating %zu bytes", requested_bytes );
            abort();
        }
        if( granted_bytes ) *granted_bytes = requested_bytes;
    }
    return current_ptr;
}

// ---------------------------------------------------------------------------------------------------------------------

// generalized alloc function purely based on stdlib
static inline void* external_nalloc( void* current_ptr, size_t current_bytes, size_t requested_bytes, size_t* granted_bytes )
{
    (void) current_bytes;
    return external_alloc( current_ptr, requested_bytes, granted_bytes );
}

// ---------------------------------------------------------------------------------------------------------------------

// internal alloc without passing current_bytes
static inline void* tbman_nalloc_no_current_bytes( void* current_ptr, size_t current_bytes, size_t requested_bytes, size_t* granted_bytes )
{
    (void) current_bytes;
    return tbman_alloc( current_ptr, requested_bytes, granted_bytes );
}

// ---------------------------------------------------------------------------------------------------------------------
/** Test of tbman diagnostic features */

typedef struct diagnostic_s { tbman_s* man; void** ptr_arr; size_t* spc_arr; size_t size; } diagnostic_s;

static void tbman_s_diagnostic_test_callback( void* arg, void* ptr, size_t space )
{
    diagnostic_s* d = arg;
    int found = false;
    for( size_t i = 0; i < d->size; i++ )
    {
        if( ptr == d->ptr_arr[ i ] )
        {
            found = true;
            ASSERT( space == d->spc_arr[ i ] );
        }
    }
    ASSERT( found );
    tbman_s_alloc( d->man, ptr, 0, NULL );
}

static void tbman_s_diagnostic_test( void )
{
    diagnostic_s diag;
    diag.man     = tbman_s_open();
    diag.size    = 1000;
    diag.ptr_arr = malloc( sizeof( void* ) * diag.size );
    diag.spc_arr = malloc( sizeof( size_t ) * diag.size );

    uint32_t rval = 1234;

    for( size_t i = 0; i < diag.size; i++ )
    {
        rval = xsg_u2( rval );
        size_t size = rval % 20000;
        diag.ptr_arr[ i ] = tbman_s_alloc( diag.man, NULL, size, &diag.spc_arr[ i ] );
    }

    ASSERT( tbman_s_total_instances( diag.man ) == diag.size );

    // the callback function frees memory
    tbman_s_for_each_instance( diag.man, tbman_s_diagnostic_test_callback, &diag );

    ASSERT( tbman_s_total_granted_space( diag.man ) == 0 );
    ASSERT( tbman_s_total_instances(     diag.man ) == 0 );

    free( diag.ptr_arr );
    free( diag.spc_arr );

    tbman_s_close( diag.man );
}

// ---------------------------------------------------------------------------------------------------------------------

void tbman_test( void )
{
    size_t table_size = 100000;
    size_t cycles     = 10;
    size_t max_alloc  = 65536;
    size_t seed       = 1237;

    bool verbose      = false; // set 'true' for more expressive test results

    printf( "Memory Manager Evaluation:\n");
    {
        printf( "\nmalloc, free, realloc (stdlib) ...\n");
        alloc_challenge( external_nalloc, table_size, cycles, max_alloc, seed, true, verbose );
    }

    {
        printf( "\ntbman_malloc, tbman_free, tbman_realloc ...\n");
        alloc_challenge( tbman_nalloc_no_current_bytes, table_size, cycles, max_alloc, seed, true, verbose );
    }

    {
        printf( "\ntbman_malloc, tbman_nfree, tbman_nrealloc ...\n");
        alloc_challenge( tbman_nalloc, table_size, cycles, max_alloc, seed, true, verbose );
    }

    {
        printf( "\ndiagnostic test ... ");
        tbman_s_diagnostic_test();
        printf( "success!\n");
    }
}

// ---------------------------------------------------------------------------------------------------------------------

int main( void )
{
    tbman_open();
    tbman_test();
    tbman_close();
}

// ---------------------------------------------------------------------------------------------------------------------

