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

/** btree on the basis of a self-balancing 2-3 tree structure.
 *  This structure can be used for well-scalable associative data management.
 *  Worst case complexity is O(log(n)) for access, insertion and deletion.
 *
 *  Internally, this solution uses a node structure with three child pointers,
 *  one parent pointer and two key-value containers.
 *  Root-state is indicated by parent==NULL.
 *  Leaf-state is indicated by child0==BNUL.
 *  Single-key-state is indicated by child2==NULL.
 *  Therefore additional state-flags are not needed.
 *
 *  Available btree structures
 *    - btree_ps: key: void*,    value: size_t
 *    - btree_vd: key: void*,    value: no dedicated value
*/

#ifndef BTREE_H
#define BTREE_H

#ifdef __cplusplus
   extern "C" {
#endif // __cplusplus

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**********************************************************************************************************************/
/**********************************************************************************************************************/
// tree of void* as key and size_t as value

typedef void* btree_ps_key_t;
typedef size_t btree_ps_val_t;

struct btree_ps_s;
typedef struct btree_ps_s btree_ps_s;

/// Creates a new btree_ip
btree_ps_s* btree_ps_s_create( void* (*alloc)( void*, size_t size ) );

/// Deletes a btree_ip
void btree_ps_s_discard( btree_ps_s* o );

/** Returns pointer to the value associated with given key.
 *  Returns NULL when the key does not exist.
 */
btree_ps_val_t* btree_ps_s_val( const btree_ps_s* o, btree_ps_key_t key );

/** Sets a key-value pair in the tree.
 *  If the key already exists, its value is overwritten.
 *  Return value:
 *    0: key, val already existed -> nothing changed
 *    1: key did not exist (key, val) was created
 *   -1: key already existed but with different value -> value was overwritten
 *   -2: internal error
 */
int btree_ps_s_set( btree_ps_s* o, btree_ps_key_t key, btree_ps_val_t val );

/** Removes a key from the tree.
 *  Return value:
 *    0: key did not exist -> nothing changed
 *    1: key found and removed
 *   -1: internal error
 */
int btree_ps_s_remove( btree_ps_s* o, btree_ps_key_t key );

/// calls a function for all tree elements
void btree_ps_s_run(   const btree_ps_s* o, void(*func)( void* arg, btree_ps_key_t key, btree_ps_val_t val ), void* arg );

/// counts entries for which func returns true; counts all entries in case func is NULL
size_t btree_ps_s_count( const btree_ps_s* o, bool(*func)( void* arg, btree_ps_key_t key, btree_ps_val_t val ), void* arg );

/// sums entries for which func returns true; sums all entries in case func is NULL
size_t btree_ps_s_sum( const btree_ps_s* o, bool(*func)( void* arg, btree_ps_key_t key, btree_ps_val_t val ), void* arg );

/// return depth of tree
size_t btree_ps_s_depth( const btree_ps_s* o );

/**********************************************************************************************************************/
/**********************************************************************************************************************/
// tree of void* as key (no dedicated value)

typedef void* btree_vd_key_t;

struct btree_vd_s;
typedef struct btree_vd_s btree_vd_s;

struct btree_vd_s;
typedef struct btree_vd_s btree_vd_s;

/// Creates a new btree_vd (allows to specify alloc function because this tree type is used in memory management)
btree_vd_s* btree_vd_s_create( void* (*alloc)( void*, size_t size ) );

/// Deletes a btree_vd
void btree_vd_s_discard( btree_vd_s* o );

/// Checks existence of key
bool btree_vd_s_exists( const btree_vd_s* o, btree_vd_key_t key );

/// Returns the largest stored key euqal or below <key>. Returns NULL in case all stored keys are larger than <key>.
btree_vd_key_t btree_vd_s_largest_below_equal( const btree_vd_s* o, btree_vd_key_t key );

/** Sets a key in the tree.
 *  Return value:
 *    0: key already existed -> nothing changed
 *    1: key did not exist and was created
 *   -2: internal error
 */
int btree_vd_s_set( btree_vd_s* o, btree_vd_key_t key );

/** Removes a key from the tree.
 *  Return value:
 *    0: key did not exist -> nothing changed
 *    1: key found and removed
 *   -1: internal error
 */
int btree_vd_s_remove( btree_vd_s* o, btree_vd_key_t key );

/// calls a function for all tree elements
void btree_vd_s_run( const btree_vd_s* o, void(*func)( void* arg, btree_vd_key_t key ), void* arg );

/// counts entries for which func returns true; counts all entries in case func is NULL
size_t btree_vd_s_count( const btree_vd_s* o, bool(*func)( void* arg, btree_vd_key_t key ), void* arg );

/// return depth of tree
size_t btree_vd_s_depth( const btree_vd_s* o );

#ifdef __cplusplus
   }
#endif // __cplusplus

#endif // BTREE_H


