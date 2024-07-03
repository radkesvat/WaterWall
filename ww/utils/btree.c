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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "btree.h"

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

/**********************************************************************************************************************/
/**********************************************************************************************************************/
/// btree_ps
/**********************************************************************************************************************/
/**********************************************************************************************************************/

typedef struct
{
    btree_ps_key_t key;
    btree_ps_val_t val;
} btree_ps_kv_s;

void btree_ps_kv_s_init( btree_ps_kv_s* o )
{
    o->key = 0;
    o->val = 0;
}

/**********************************************************************************************************************/

/** Node of a 2-3 btree.
 *  Child pointers can have one of three states:
 *  NULL: corresponding key-value pair is not used (for normal nodes this state only applies to child2)
 *  BNUL_PS: node is a leaf
 *  else: node has children
 */
typedef struct btree_node_ps_s
{
    btree_ps_kv_s  kv1;
    btree_ps_kv_s  kv2;
    struct btree_node_ps_s* parent;
    struct btree_node_ps_s* child0;
    struct btree_node_ps_s* child1;
    struct btree_node_ps_s* child2;
} btree_node_ps_s;

// ---------------------------------------------------------------------------------------------------------------------

/// children of leaf-nodes point to btree_node_ps_s_null
btree_node_ps_s btree_node_ps_s_null_g = { { 0, 0 }, { 0, 0 }, NULL, NULL, NULL, NULL };
#define BNUL_PS ( &btree_node_ps_s_null_g )

// ---------------------------------------------------------------------------------------------------------------------

void btree_node_ps_s_init( btree_node_ps_s* o )
{
    btree_ps_kv_s_init( &o->kv1 );
    btree_ps_kv_s_init( &o->kv2 );
    o->parent = o->child0 = o->child1 = o->child2 = NULL;
}

// ---------------------------------------------------------------------------------------------------------------------

btree_node_ps_s* btree_node_ps_s_find( btree_node_ps_s* root, btree_ps_key_t key )
{
    if( !root ) return NULL;
    btree_node_ps_s* node = NULL;
    while( root->child0 != BNUL_PS && root != node )
    {
        node = root;
        root = ( key < node->kv1.key )                                         ? node->child0 :
               ( !node->child2 && key > node->kv1.key )                        ? node->child1 :
               (  node->child2 && key > node->kv2.key )                        ? node->child2 :
               (  node->child2 && key > node->kv1.key && key < node->kv2.key ) ? node->child1 : node;
    }
    return root;
}

// ---------------------------------------------------------------------------------------------------------------------

void btree_node_ps_s_run( const btree_node_ps_s* root, void(*func)( void* arg, btree_ps_key_t key, btree_ps_val_t val ), void* arg )
{
    if( !root ) return;
    if( !func ) return;
    if( root->child0 )
    {
        if( root->child0 != BNUL_PS ) btree_node_ps_s_run( root->child0, func, arg );
    }
    if( root->child1 )
    {
        func( arg, root->kv1.key, root->kv1.val );
        if( root->child1 != BNUL_PS ) btree_node_ps_s_run( root->child1, func, arg );
    }
    if( root->child2 )
    {
        func( arg, root->kv2.key, root->kv2.val );
        if( root->child2 != BNUL_PS ) btree_node_ps_s_run( root->child2, func, arg );
    }
}

// ---------------------------------------------------------------------------------------------------------------------

size_t btree_node_ps_s_count( const btree_node_ps_s* root, bool (*func)( void* arg, btree_ps_key_t key, btree_ps_val_t val ), void* arg )
{
    size_t count = 0;
    if( !root ) return count;
    if( root->child0 )
    {
        if( root->child0 != BNUL_PS ) count += btree_node_ps_s_count( root->child0, func, arg );
    }
    if( root->child1 )
    {
        count += ( func ) ? func( arg, root->kv1.key, root->kv1.val ) : 1;
        if( root->child1 != BNUL_PS ) count += btree_node_ps_s_count( root->child1, func, arg );
    }
    if( root->child2 )
    {
        count += ( func ) ? func( arg, root->kv2.key, root->kv2.val ) : 1;
        if( root->child2 != BNUL_PS ) count += btree_node_ps_s_count( root->child2, func, arg );
    }
    return count;
}

// ---------------------------------------------------------------------------------------------------------------------

size_t btree_node_ps_s_sum( const btree_node_ps_s* root, bool (*func)( void* arg, btree_ps_key_t key, btree_ps_val_t val ), void* arg )
{
    size_t sum = 0;
    if( !root ) return sum;
    if( root->child0 )
    {
        if( root->child0 != BNUL_PS ) sum += btree_node_ps_s_sum( root->child0, func, arg );
    }
    if( root->child1 )
    {
        sum += root->kv1.val * ( ( func ) ? func( arg, root->kv1.key, root->kv1.val ) : 1 );
        if( root->child1 != BNUL_PS ) sum += btree_node_ps_s_sum( root->child1, func, arg );
    }
    if( root->child2 )
    {
        sum += root->kv2.val * ( ( func ) ? func( arg, root->kv2.key, root->kv2.val ) : 1 );
        if( root->child2 != BNUL_PS ) sum += btree_node_ps_s_sum( root->child2, func, arg );
    }
    return sum;
}

// ---------------------------------------------------------------------------------------------------------------------

size_t btree_node_ps_s_keys( btree_node_ps_s* root )
{
    if( !root || root == BNUL_PS ) return 0;
    size_t keys = root->child2 ? 2 : 1;
    keys += btree_node_ps_s_keys( root->child0 );
    keys += btree_node_ps_s_keys( root->child1 );
    if( root->child2 ) keys += btree_node_ps_s_keys( root->child2 );
    return keys;
}

// ---------------------------------------------------------------------------------------------------------------------

size_t btree_node_ps_s_depth( btree_node_ps_s* root )
{
    if( !root || root == BNUL_PS ) return 0;
    return 1 + btree_node_ps_s_depth( root->child0 );
}

// ---------------------------------------------------------------------------------------------------------------------

void btree_node_ps_s_set_parent_child0( btree_node_ps_s* o ) { if( o->child0 && o->child0 != BNUL_PS ) o->child0->parent = o; }
void btree_node_ps_s_set_parent_child1( btree_node_ps_s* o ) { if( o->child1 && o->child1 != BNUL_PS ) o->child1->parent = o; }
void btree_node_ps_s_set_parent_child2( btree_node_ps_s* o ) { if( o->child2 && o->child2 != BNUL_PS ) o->child2->parent = o; }
int  btree_node_ps_s_is_leaf(  btree_node_ps_s* o )          { return o->child0 == BNUL_PS; }
int  btree_node_ps_s_is_full(  btree_node_ps_s* o )          { return o->child2 != NULL; }
int  btree_node_ps_s_is_empty( btree_node_ps_s* o )          { return o->child1 == NULL; }

// ---------------------------------------------------------------------------------------------------------------------

void btree_node_ps_s_check_consistency( btree_node_ps_s* o )
{
    if( btree_node_ps_s_null_g.kv1.key != 0    ) ERR( "btree_node_ps_s_null was modified" );
    if( btree_node_ps_s_null_g.kv1.val != 0    ) ERR( "btree_node_ps_s_null was modified" );
    if( btree_node_ps_s_null_g.kv2.key != 0    ) ERR( "btree_node_ps_s_null was modified" );
    if( btree_node_ps_s_null_g.kv2.val != 0    ) ERR( "btree_node_ps_s_null was modified" );
    if( btree_node_ps_s_null_g.parent  != NULL ) ERR( "btree_node_ps_s_null was modified" );
    if( btree_node_ps_s_null_g.child0  != NULL ) ERR( "btree_node_ps_s_null was modified" );
    if( btree_node_ps_s_null_g.child1  != NULL ) ERR( "btree_node_ps_s_null was modified" );
    if( btree_node_ps_s_null_g.child2  != NULL ) ERR( "btree_node_ps_s_null was modified" );

    if( !o ) return;
    if( btree_node_ps_s_is_empty( o ) ) ERR( "empty node" );
    if( o->child0 == NULL )       ERR( "deleted leaf" );
    if( o->child1 && o->child1 != BNUL_PS )
    {
        if( o != o->child0->parent ) ERR( "child0 incorrect parent" );
        if( o != o->child1->parent ) ERR( "child1 incorrect parent" );
        btree_node_ps_s_check_consistency( o->child0 );
        btree_node_ps_s_check_consistency( o->child1 );
        if(                      o->kv1.key <= o->child0->kv1.key ) ERR( "(%zu <= %zu)", o->kv1.key, o->child0->kv1.key );
        if( o->child0->child2 && o->kv1.key <= o->child0->kv2.key ) ERR( "(%zu <= %zu)", o->kv1.key, o->child0->kv2.key );
        if(                      o->kv1.key >= o->child1->kv1.key ) ERR( "(%zu >= %zu)", o->kv1.key, o->child1->kv1.key );
        if( o->child1->child2 && o->kv1.key >= o->child1->kv2.key ) ERR( "(%zu >= %zu)", o->kv1.key, o->child1->kv2.key );
    }
    if( o->child2 && o->child2 != BNUL_PS )
    {
        if( o->kv1.key >= o->kv2.key ) ERR( "(%zu >= %zu)", o->kv1.key, o->kv2.key );
        if( o != o->child2->parent ) ERR( "child2 incorrect parent" );
        btree_node_ps_s_check_consistency( o->child2 );
        if(                      o->kv2.key <= o->child1->kv1.key ) ERR( "(%zu <= %zu)", o->kv2.key, o->child1->kv1.key );
        if( o->child1->child2 && o->kv2.key <= o->child1->kv2.key ) ERR( "(%zu <= %zu)", o->kv2.key, o->child1->kv2.key );
        if(                      o->kv2.key >= o->child2->kv1.key ) ERR( "(%zu >= %zu)", o->kv2.key, o->child2->kv1.key );
        if( o->child2->child2 && o->kv2.key >= o->child2->kv2.key ) ERR( "(%zu >= %zu)", o->kv2.key, o->child2->kv2.key );
    }
}

// ---------------------------------------------------------------------------------------------------------------------

/**********************************************************************************************************************/

// ---------------------------------------------------------------------------------------------------------------------

struct btree_ps_s
{
    btree_node_ps_s* root;
    btree_node_ps_s* chain_beg; // begin of chain of blocks of btree_node_ps_s[] with last element being pointer to next block
    btree_node_ps_s* chain_end; // end of chain of blocks
    btree_node_ps_s* chain_ins; // pointer for new insertions
    btree_node_ps_s* del_chain; // chain of deleted elements (preferably used by new insertions)
    void* (*alloc)( void*, size_t size ); // alloc function
    size_t   block_size;
};

// ---------------------------------------------------------------------------------------------------------------------

btree_ps_s* btree_ps_s_create( void* (*alloc)( void*, size_t size ) )
{
    btree_ps_s* o = NULL;
    if( alloc )
    {
        o = alloc( NULL, sizeof( btree_ps_s ) );
        o->alloc = alloc;
    }
    else
    {
        o = alloc( NULL, sizeof( btree_ps_s ) );
        o->alloc = alloc;
    }
    o->root      = NULL;
    o->chain_beg = NULL;
    o->chain_end = NULL;
    o->chain_ins = NULL;
    o->del_chain = NULL;
    o->block_size = 1024;
    return o;
}

// ---------------------------------------------------------------------------------------------------------------------

void btree_ps_s_discard( btree_ps_s* o )
{
    o->root = NULL;

    btree_node_ps_s* chain_beg = o->chain_beg;
    while( chain_beg )
    {
        btree_node_ps_s* new_beg = *( btree_node_ps_s** )( chain_beg + o->block_size );
        o->alloc( chain_beg, 0 );
        chain_beg = new_beg;
    }

    o->alloc( o, 0 );
}

// ---------------------------------------------------------------------------------------------------------------------

btree_node_ps_s* btree_ps_s_new_node( btree_ps_s* o )
{
    if( o->del_chain )
    {
        btree_node_ps_s* new_node = o->del_chain;
        o->del_chain = new_node->parent;
        btree_node_ps_s_init( new_node );
        return new_node;
    }
    else
    {
        if( o->chain_ins == o->chain_end )
        {
            btree_node_ps_s* new_ptr = o->alloc( NULL, o->block_size * sizeof( btree_node_ps_s ) + sizeof( btree_node_ps_s* ) );
            if( !o->chain_beg )
            {
                o->chain_beg = new_ptr;
            }
            else
            {
                ( ( btree_node_ps_s** )( o->chain_end ) )[ 0 ] = new_ptr;
            }
            o->chain_ins = new_ptr;
            o->chain_end = new_ptr + o->block_size;
            *( btree_node_ps_s** )( o->chain_end ) = NULL;
        }
        btree_node_ps_s* new_node = o->chain_ins;
        btree_node_ps_s_init( new_node );
        o->chain_ins++;
        return new_node;
    }
}

// ---------------------------------------------------------------------------------------------------------------------

// Deleted nodes are marked by setting all children NULL
// and chained together using pointer btree_node_ps_s.parent.
void btree_ps_s_delete_node( btree_ps_s* o, btree_node_ps_s* node )
{
    node->child0 = NULL;
    node->child1 = NULL;
    node->child2 = NULL;
    node->parent = o->del_chain;
    o->del_chain = node;
}

// ---------------------------------------------------------------------------------------------------------------------

// recursively pushes an element into the tree
void btree_ps_s_push( btree_ps_s* o, btree_node_ps_s* node, btree_ps_kv_s* kv, btree_node_ps_s* child0, btree_node_ps_s* child1 )
{
    if( btree_node_ps_s_is_full( node ) )
    {
        btree_node_ps_s* l_node = node;
        btree_node_ps_s* r_node = btree_ps_s_new_node( o );
        btree_ps_kv_s root_kv;

        if( kv->key < node->kv1.key )
        {
            root_kv        = l_node->kv1;
            r_node->kv1    = l_node->kv2;
            r_node->child0 = l_node->child1;
            r_node->child1 = l_node->child2;
            l_node->kv1    = *kv;
            l_node->child0 = child0;
            l_node->child1 = child1;
        }
        else if( kv->key > node->kv2.key )
        {
            root_kv        = l_node->kv2;
            r_node->kv1    = *kv;
            r_node->child0 = child0;
            r_node->child1 = child1;
        }
        else
        {
            root_kv        = *kv;
            r_node->kv1    = l_node->kv2;
            r_node->child1 = l_node->child2;
            r_node->child0 = child1;
            l_node->child1 = child0;
        }
        r_node->child2 = NULL;
        l_node->child2 = NULL;

        btree_node_ps_s_set_parent_child0( r_node );
        btree_node_ps_s_set_parent_child1( r_node );
        btree_node_ps_s_set_parent_child0( l_node );
        btree_node_ps_s_set_parent_child1( l_node );

        if( l_node->parent )
        {
            btree_ps_s_push( o, l_node->parent, &root_kv, l_node, r_node );
        }
        else
        {
            o->root = btree_ps_s_new_node( o );
            o->root->kv1    = root_kv;
            o->root->child0 = l_node;
            o->root->child1 = r_node;
            l_node->parent  = o->root;
            r_node->parent  = o->root;
        }
    }
    else
    {
        if( kv->key < node->kv1.key )
        {
            node->kv2    = node->kv1;
            node->kv1    = *kv;
            node->child2 = node->child1;
            node->child1 = child1;
            node->child0 = child0;
            btree_node_ps_s_set_parent_child0( node );
            btree_node_ps_s_set_parent_child1( node );
            btree_node_ps_s_set_parent_child2( node );
        }
        else
        {
            node->kv2    = *kv;
            node->child2 = child1;
            node->child1 = child0;
            btree_node_ps_s_set_parent_child1( node );
            btree_node_ps_s_set_parent_child2( node );
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------

// Recursively pulls an element from a non-leaf into an empty child node
void btree_ps_s_pull( btree_ps_s* o, btree_node_ps_s* node )
{
    if( btree_node_ps_s_is_empty( node->child0 ) )
    {
        if( btree_node_ps_s_is_full( node->child1 ) )
        {
            node->child0->kv1    = node->kv1;
            node->child0->child1 = node->child1->child0;
            btree_node_ps_s_set_parent_child1( node->child0 );
            node->kv1            = node->child1->kv1;
            node->child1->kv1    = node->child1->kv2;
            node->child1->child0 = node->child1->child1;
            node->child1->child1 = node->child1->child2;
            node->child1->child2 = NULL;
        }
        else if( btree_node_ps_s_is_full( node ) )
        {
            node->child1->kv2    = node->child1->kv1;
            node->child1->kv1    = node->kv1;
            node->child1->child2 = node->child1->child1;
            node->child1->child1 = node->child1->child0;
            node->child1->child0 = node->child0->child0;
            btree_node_ps_s_set_parent_child0( node->child1 );
            btree_ps_s_delete_node( o, node->child0 );
            node->kv1    = node->kv2;
            node->child0 = node->child1;
            node->child1 = node->child2;
            node->child2 = NULL;
        }
        else
        {
            node->child1->kv2    = node->child1->kv1;
            node->child1->kv1    = node->kv1;
            node->child1->child2 = node->child1->child1;
            node->child1->child1 = node->child1->child0;
            node->child1->child0 = node->child0->child0;
            btree_node_ps_s_set_parent_child0( node->child1 );
            btree_ps_s_delete_node( o, node->child0 );
            node->child0 = node->child1;
            node->child1 = node->child2 = NULL;
            if( node->parent )
            {
                btree_ps_s_pull( o, node->parent );
            }
            else
            {
                o->root = node->child0;
                o->root->parent = NULL;
                btree_ps_s_delete_node( o, node );
            }
        }
    }
    else if( btree_node_ps_s_is_empty( node->child1 ) )
    {
        if( btree_node_ps_s_is_full( node->child0 ) )
        {
            node->child1->kv1    = node->kv1;
            node->child1->child1 = node->child1->child0;
            node->child1->child0 = node->child0->child2;
            btree_node_ps_s_set_parent_child0( node->child1 );
            node->kv1            = node->child0->kv2;
            node->child0->child2 = NULL;
        }
        else if( btree_node_ps_s_is_full( node ) )
        {
            node->child0->kv2    = node->kv1;
            node->child0->child2 = node->child1->child0;
            btree_node_ps_s_set_parent_child2( node->child0 );
            btree_ps_s_delete_node( o, node->child1 );
            node->kv1    = node->kv2;
            node->child1 = node->child2;
            node->child2 = NULL;
        }
        else
        {
            node->child0->kv2    = node->kv1;
            node->child0->child2 = node->child1->child0;
            btree_node_ps_s_set_parent_child2( node->child0 );
            btree_ps_s_delete_node( o, node->child1 );
            node->child1 = node->child2 = NULL;
            if( node->parent )
            {
                btree_ps_s_pull( o, node->parent );
            }
            else
            {
                o->root = node->child0;
                o->root->parent = NULL;
                btree_ps_s_delete_node( o, node );
            }
        }
    }
    else // node->child2 is empty
    {
        if( btree_node_ps_s_is_full( node ) )
        {
            if( btree_node_ps_s_is_full( node->child1 ) )
            {
                node->child2->kv1 = node->kv2;
                node->child2->child1 = node->child2->child0;
                node->child2->child0 = node->child1->child2;
                btree_node_ps_s_set_parent_child0( node->child2 );
                node->kv2            = node->child1->kv2;
                node->child1->child2 = NULL;
            }
            else
            {
                node->child1->kv2    = node->kv2;
                node->child1->child2 = node->child2->child0;
                btree_node_ps_s_set_parent_child2( node->child1 );
                btree_ps_s_delete_node( o, node->child2 );
                node->child2         = NULL;
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------

btree_ps_val_t* btree_ps_s_val( const btree_ps_s* o, btree_ps_key_t key )
{
    if( !o )    return NULL;
    btree_node_ps_s* node = btree_node_ps_s_find( o->root, key );
    if( !node ) return NULL;
    if( node->kv1.key == key ) return &node->kv1.val;
    if( node->child2 && node->kv2.key == key ) return &node->kv2.val;
    return NULL;
}

// ---------------------------------------------------------------------------------------------------------------------

int btree_ps_s_set( btree_ps_s* o, btree_ps_key_t key, btree_ps_val_t val )
{
    if( !o ) return -2;
    if( !o->root )
    {
        o->root = btree_ps_s_new_node( o );
        o->root->child0 = o->root->child1 = BNUL_PS;
        o->root->child2 = NULL;
        o->root->kv1.key = key;
        o->root->kv1.val = val;
        return 1;
    }

    btree_node_ps_s* node = btree_node_ps_s_find( o->root, key );
    if( !node ) return -2;

    if( node->kv1.key == key )
    {
        if( node->kv1.val == val ) return 0;
        node->kv1.val = val;
        return -1;
    }
    else if( node->child2 && node->kv2.key == key )
    {
        if( node->kv2.val == val ) return 0;
        node->kv2.val = val;
        return -1;
    }
    else
    {
        btree_ps_kv_s kv = { key, val };
        btree_ps_s_push( o, node, &kv, BNUL_PS, BNUL_PS );
        return 1;
    }
}

// ---------------------------------------------------------------------------------------------------------------------

int btree_ps_s_remove( btree_ps_s* o, btree_ps_key_t key )
{
    if( !o       ) return -1;
    if( !o->root ) return  0;
    btree_node_ps_s* node = btree_node_ps_s_find( o->root, key );
    if( !node    ) return -1;

    if( node->kv1.key == key )
    {
        if( !btree_node_ps_s_is_leaf( node ) )
        {
            btree_node_ps_s* trace = node->child0;
            while( !btree_node_ps_s_is_leaf( trace ) ) trace = ( trace->child2 ) ? trace->child2 : trace->child1;
            if( btree_node_ps_s_is_full( trace ) )
            {
                node->kv1   = trace->kv2;
                trace->child2 = NULL;
            }
            else
            {
                node->kv1 = trace->kv1;
                trace->child1 = trace->child2 = NULL;
                btree_ps_s_pull( o, trace->parent );
            }
        }
        else if( btree_node_ps_s_is_full( node ) )
        {
            node->kv1 = node->kv2;
            node->child2 = NULL;
        }
        else
        {
            node->child1 = node->child2 = NULL;
            if( node->parent )
            {
                btree_ps_s_pull( o, node->parent );
            }
            else
            {
                btree_ps_s_delete_node( o, node );
                o->root = NULL;
            }
        }
        return 1;
    }

    if( node->kv2.key == key )
    {
        if( !btree_node_ps_s_is_leaf( node ) )
        {
            btree_node_ps_s* trace = ( node->child2 ) ? node->child2 : node->child1;
            while( !btree_node_ps_s_is_leaf( trace ) ) trace = trace->child0;
            if( btree_node_ps_s_is_full( trace ) )
            {
                node->kv2     = trace->kv1;
                trace->kv1    = trace->kv2;
                trace->child2 = NULL;
            }
            else
            {
                node->kv2   = trace->kv1;
                trace->child1 = trace->child2 = NULL;
                btree_ps_s_pull( o, trace->parent );
            }
        }
        else if( btree_node_ps_s_is_full( node ) )
        {
            node->child2 = NULL;
        }
        else
        {
            node->child1 = node->child2 = NULL;
            if( node->parent )
            {
                btree_ps_s_pull( o, node->parent );
            }
            else
            {
                btree_ps_s_delete_node( o, node );
                o->root = NULL;
            }
        }
        return 1;
    }
    return 0;
}

// ---------------------------------------------------------------------------------------------------------------------

void btree_ps_s_run( const btree_ps_s* o, void(*func)( void* arg, btree_ps_key_t key, btree_ps_val_t val ), void* arg )
{
    btree_node_ps_s_run( o->root, func, arg );
}

// ---------------------------------------------------------------------------------------------------------------------

size_t btree_ps_s_count( const btree_ps_s* o, bool(*func)( void* arg, btree_ps_key_t key, btree_ps_val_t val ), void* arg )
{
    return btree_node_ps_s_count( o->root, func, arg );
}

// ---------------------------------------------------------------------------------------------------------------------

size_t btree_ps_s_sum( const btree_ps_s* o, bool(*func)( void* arg, btree_ps_key_t key, btree_ps_val_t val ), void* arg )
{
    return btree_node_ps_s_sum( o->root, func, arg );
}

// ---------------------------------------------------------------------------------------------------------------------

size_t btree_ps_s_depth( const btree_ps_s* o )
{
    return btree_node_ps_s_depth( o->root );
}

// ---------------------------------------------------------------------------------------------------------------------

void print_btree_ps_s_status( btree_ps_s* o )
{
    size_t blocks = 0;
    size_t nodes = 0;
    size_t deleted_nodes = 0;
    if( o->chain_beg )
    {
        btree_node_ps_s* chain_beg = o->chain_beg;
        while( chain_beg )
        {
            chain_beg = *( btree_node_ps_s** )( chain_beg + o->block_size );
            blocks++;
        }
        nodes = blocks * o->block_size - ( o->chain_end - o->chain_ins );
    }
    if( o->del_chain )
    {
        btree_node_ps_s* del_chain = o->del_chain;
        while( del_chain )
        {
            del_chain = del_chain->parent;
            deleted_nodes++;
        }
    }

    size_t used_nodes = nodes - deleted_nodes;
    printf( "keys ........... %zu\n", btree_node_ps_s_keys( o->root ) );
    printf( "nodes .......... %zu\n", used_nodes );
    printf( "keys/nodes ..... %5.4f\n", used_nodes > 0 ? ( double )( btree_node_ps_s_keys( o->root ) ) / used_nodes : 0 );
    printf( "depth .......... %zu\n", btree_node_ps_s_depth( o->root ) );
    printf( "block size ..... %zu\n", o->block_size );
    printf( "blocks ......... %zu\n", blocks );
    printf( "deleted nodes .. %zu\n", deleted_nodes );
}

// ---------------------------------------------------------------------------------------------------------------------

/**********************************************************************************************************************/
/**********************************************************************************************************************/
/// btree_vd
/**********************************************************************************************************************/
/**********************************************************************************************************************/

// E use the specifier 'kv' in this structure for consistency reasons even though this tree has no dedicated value
typedef struct
{
    btree_vd_key_t key;
} btree_vd_kv_s;

void btree_vd_kv_s_init( btree_vd_kv_s* o )
{
    o->key = 0;
}

/**********************************************************************************************************************/

/** Node of a 2-3 btree.
 *  Child pointers can have one of three states:
 *  NULL: corresponding key-value pair is not used (for normal nodes this state only applies to child2)
 *  BNUL_VP: node is a leaf
 *  else: node has children
 */
typedef struct btree_node_vd_s
{
    btree_vd_kv_s  kv1;
    btree_vd_kv_s  kv2;
    struct btree_node_vd_s* parent;
    struct btree_node_vd_s* child0;
    struct btree_node_vd_s* child1;
    struct btree_node_vd_s* child2;
} btree_node_vd_s;

/// children of leaf-nodes point to btree_node_vd_s_null
btree_node_vd_s btree_node_vd_s_null_g = { { NULL }, { NULL }, NULL, NULL, NULL, NULL };
#define BNUL_VP ( &btree_node_vd_s_null_g )

// ---------------------------------------------------------------------------------------------------------------------

void btree_node_vd_s_init( btree_node_vd_s* o )
{
    btree_vd_kv_s_init( &o->kv1 );
    btree_vd_kv_s_init( &o->kv2 );
    o->parent = o->child0 = o->child1 = o->child2 = NULL;
}

// ---------------------------------------------------------------------------------------------------------------------

btree_node_vd_s* btree_node_vd_s_find( btree_node_vd_s* root, btree_vd_key_t key )
{
    if( !root ) return NULL;
    btree_node_vd_s* node = NULL;
    while( root->child0 != BNUL_VP && root != node )
    {
        node = root;
        root = ( key < node->kv1.key )                                         ? node->child0 :
               ( !node->child2 && key > node->kv1.key )                        ? node->child1 :
               (  node->child2 && key > node->kv2.key )                        ? node->child2 :
               (  node->child2 && key > node->kv1.key && key < node->kv2.key ) ? node->child1 : node;
    }
    return root;
}

// ---------------------------------------------------------------------------------------------------------------------

btree_vd_key_t btree_node_vd_s_largest_below_equal( btree_node_vd_s* root, btree_vd_key_t key )
{
    if( !root ) return 0;
    if( root->child0 == BNUL_VP )
    {
        if( ( root->child2 ) && key >= root->kv2.key ) return root->kv2.key;
        return ( key >= root->kv1.key ) ? root->kv1.key : 0;
    }
    else if( ( root->child2 ) && key >= root->kv2.key )
    {
        btree_vd_key_t branch_key = btree_node_vd_s_largest_below_equal( root->child2, key );
        return ( branch_key >= root->kv2.key ) ? branch_key : root->kv2.key;
    }
    else if( key >= root->kv1.key )
    {
        btree_vd_key_t branch_key = btree_node_vd_s_largest_below_equal( root->child1, key );
        return ( branch_key >= root->kv1.key ) ? branch_key : root->kv1.key;
    }
    else
    {
        return btree_node_vd_s_largest_below_equal( root->child0, key );
    }
}

// ---------------------------------------------------------------------------------------------------------------------

void btree_node_vd_s_run( const btree_node_vd_s* root, void(*func)( void* arg, btree_vd_key_t key ), void* arg )
{
    if( !root ) return;
    if( !func ) return;
    if( root->child0 )
    {
        if( root->child0 != BNUL_VP ) btree_node_vd_s_run( root->child0, func, arg );
    }
    if( root->child1 )
    {
        func( arg, root->kv1.key );
        if( root->child1 != BNUL_VP ) btree_node_vd_s_run( root->child1, func, arg );
    }
    if( root->child2 )
    {
        func( arg, root->kv2.key );
        if( root->child2 != BNUL_VP ) btree_node_vd_s_run( root->child2, func, arg );
    }
}

// ---------------------------------------------------------------------------------------------------------------------

size_t btree_node_vd_s_count( const btree_node_vd_s* root, bool (*func)( void* arg, btree_vd_key_t key ), void* arg )
{
    size_t count = 0;
    if( !root ) return count;
    if( root->child0 )
    {
        if( root->child0 != BNUL_VP ) count += btree_node_vd_s_count( root->child0, func, arg );
    }
    if( root->child1 )
    {
        count += ( func ) ? func( arg, root->kv1.key ) : 1;
        if( root->child1 != BNUL_VP ) count += btree_node_vd_s_count( root->child1, func, arg );
    }
    if( root->child2 )
    {
        count += ( func ) ? func( arg, root->kv2.key ) : 1;
        if( root->child2 != BNUL_VP ) count += btree_node_vd_s_count( root->child2, func, arg );
    }
    return count;
}

// ---------------------------------------------------------------------------------------------------------------------

size_t btree_node_vd_s_keys( btree_node_vd_s* root )
{
    if( !root || root == BNUL_VP ) return 0;
    size_t keys = root->child2 ? 2 : 1;
    keys += btree_node_vd_s_keys( root->child0 );
    keys += btree_node_vd_s_keys( root->child1 );
    if( root->child2 ) keys += btree_node_vd_s_keys( root->child2 );
    return keys;
}

// ---------------------------------------------------------------------------------------------------------------------

size_t btree_node_vd_s_depth( btree_node_vd_s* root )
{
    if( !root || root == BNUL_VP ) return 0;
    return 1 + btree_node_vd_s_depth( root->child0 );
}

// ---------------------------------------------------------------------------------------------------------------------

void btree_node_vd_s_set_parent_child0( btree_node_vd_s* o ) { if( o->child0 && o->child0 != BNUL_VP ) o->child0->parent = o; }
void btree_node_vd_s_set_parent_child1( btree_node_vd_s* o ) { if( o->child1 && o->child1 != BNUL_VP ) o->child1->parent = o; }
void btree_node_vd_s_set_parent_child2( btree_node_vd_s* o ) { if( o->child2 && o->child2 != BNUL_VP ) o->child2->parent = o; }
int  btree_node_vd_s_is_leaf(  btree_node_vd_s* o )          { return o->child0 == BNUL_VP; }
int  btree_node_vd_s_is_full(  btree_node_vd_s* o )          { return o->child2 != NULL; }
int  btree_node_vd_s_is_empty( btree_node_vd_s* o )          { return o->child1 == NULL; }

// ---------------------------------------------------------------------------------------------------------------------

void btree_node_vd_s_check_consistency( btree_node_vd_s* o )
{
    if( btree_node_vd_s_null_g.kv1.key != 0    ) ERR( "btree_node_vd_s_null was modified" );
    if( btree_node_vd_s_null_g.kv2.key != 0    ) ERR( "btree_node_vd_s_null was modified" );
    if( btree_node_vd_s_null_g.parent  != NULL ) ERR( "btree_node_vd_s_null was modified" );
    if( btree_node_vd_s_null_g.child0  != NULL ) ERR( "btree_node_vd_s_null was modified" );
    if( btree_node_vd_s_null_g.child1  != NULL ) ERR( "btree_node_vd_s_null was modified" );
    if( btree_node_vd_s_null_g.child2  != NULL ) ERR( "btree_node_vd_s_null was modified" );

    if( !o ) return;
    if( btree_node_vd_s_is_empty( o ) ) ERR( "empty node" );
    if( o->child0 == NULL )       ERR( "deleted leaf" );
    if( o->child1 && o->child1 != BNUL_VP )
    {
        if( o != o->child0->parent ) ERR( "child0 incorrect parent" );
        if( o != o->child1->parent ) ERR( "child1 incorrect parent" );
        btree_node_vd_s_check_consistency( o->child0 );
        btree_node_vd_s_check_consistency( o->child1 );
        if(                      o->kv1.key <= o->child0->kv1.key ) ERR( "(%zu <= %zu)", o->kv1.key, o->child0->kv1.key );
        if( o->child0->child2 && o->kv1.key <= o->child0->kv2.key ) ERR( "(%zu <= %zu)", o->kv1.key, o->child0->kv2.key );
        if(                      o->kv1.key >= o->child1->kv1.key ) ERR( "(%zu >= %zu)", o->kv1.key, o->child1->kv1.key );
        if( o->child1->child2 && o->kv1.key >= o->child1->kv2.key ) ERR( "(%zu >= %zu)", o->kv1.key, o->child1->kv2.key );
    }
    if( o->child2 && o->child2 != BNUL_VP )
    {
        if( o->kv1.key >= o->kv2.key ) ERR( "(%zu >= %zu)", o->kv1.key, o->kv2.key );
        if( o != o->child2->parent ) ERR( "child2 incorrect parent" );
        btree_node_vd_s_check_consistency( o->child2 );
        if(                      o->kv2.key <= o->child1->kv1.key ) ERR( "(%zu <= %zu)", o->kv2.key, o->child1->kv1.key );
        if( o->child1->child2 && o->kv2.key <= o->child1->kv2.key ) ERR( "(%zu <= %zu)", o->kv2.key, o->child1->kv2.key );
        if(                      o->kv2.key >= o->child2->kv1.key ) ERR( "(%zu >= %zu)", o->kv2.key, o->child2->kv1.key );
        if( o->child2->child2 && o->kv2.key >= o->child2->kv2.key ) ERR( "(%zu >= %zu)", o->kv2.key, o->child2->kv2.key );
    }
}

// ---------------------------------------------------------------------------------------------------------------------

/**********************************************************************************************************************/

// ---------------------------------------------------------------------------------------------------------------------

struct btree_vd_s
{
    btree_node_vd_s* root;
    btree_node_vd_s* chain_beg;   // begin of chain of blocks of btree_node_vd_s[] with last element being pointer to next block
    btree_node_vd_s* chain_end;   // end of chain of blocks
    btree_node_vd_s* chain_ins;   // pointer for new insertions
    btree_node_vd_s* del_chain;   // chain of deleted elements (preferably used by new insertions)
    void* (*alloc)( void*, size_t size ); // alloc function
    size_t   block_size;
};

// ---------------------------------------------------------------------------------------------------------------------

btree_vd_s* btree_vd_s_create( void* (*alloc)( void*, size_t size ) )
{
    btree_vd_s* o = NULL;
    if( alloc )
    {
        o = alloc( NULL, sizeof( btree_vd_s ) );
        o->alloc = alloc;
    }
    else
    {
        o = alloc( NULL, sizeof( btree_vd_s ) );
        o->alloc = alloc;
    }
    o->root      = NULL;
    o->chain_beg = NULL;
    o->chain_end = NULL;
    o->chain_ins = NULL;
    o->del_chain = NULL;
    o->block_size = 1024;
    return o;
}

// ---------------------------------------------------------------------------------------------------------------------

void btree_vd_s_discard( btree_vd_s* o )
{
    o->root = NULL;

    btree_node_vd_s* chain_beg = o->chain_beg;
    while( chain_beg )
    {
        btree_node_vd_s* new_beg = *( btree_node_vd_s** )( chain_beg + o->block_size );
        o->alloc( chain_beg, 0 );
        chain_beg = new_beg;
    }

    o->alloc( o, 0 );
}

// ---------------------------------------------------------------------------------------------------------------------

btree_node_vd_s* btree_vd_s_new_node( btree_vd_s* o )
{
    if( o->del_chain )
    {
        btree_node_vd_s* new_node = o->del_chain;
        o->del_chain = new_node->parent;
        btree_node_vd_s_init( new_node );
        return new_node;
    }
    else
    {
        if( o->chain_ins == o->chain_end )
        {
            btree_node_vd_s* new_ptr = o->alloc( NULL, o->block_size * sizeof( btree_node_vd_s ) + sizeof( btree_node_vd_s* ) );
            if( !o->chain_beg )
            {
                o->chain_beg = new_ptr;
            }
            else
            {
                ( ( btree_node_vd_s** )( o->chain_end ) )[ 0 ] = new_ptr;
            }
            o->chain_ins = new_ptr;
            o->chain_end = new_ptr + o->block_size;
            *( btree_node_vd_s** )( o->chain_end ) = NULL;
        }
        btree_node_vd_s* new_node = o->chain_ins;
        btree_node_vd_s_init( new_node );
        o->chain_ins++;
        return new_node;
    }
}

// ---------------------------------------------------------------------------------------------------------------------

// Deleted nodes are marked by setting all children NULL
// and chained together using pointer btree_node_vd_s.parent.
void btree_vd_s_delete_node( btree_vd_s* o, btree_node_vd_s* node )
{
    node->child0 = NULL;
    node->child1 = NULL;
    node->child2 = NULL;
    node->parent = o->del_chain;
    o->del_chain = node;
}

// ---------------------------------------------------------------------------------------------------------------------

// recursively pushes an element into the tree
void btree_vd_s_push( btree_vd_s* o, btree_node_vd_s* node, btree_vd_kv_s* kv, btree_node_vd_s* child0, btree_node_vd_s* child1 )
{
    if( btree_node_vd_s_is_full( node ) )
    {
        btree_node_vd_s* l_node = node;
        btree_node_vd_s* r_node = btree_vd_s_new_node( o );
        btree_vd_kv_s root_kv;

        if( kv->key < node->kv1.key )
        {
            root_kv        = l_node->kv1;
            r_node->kv1    = l_node->kv2;
            r_node->child0 = l_node->child1;
            r_node->child1 = l_node->child2;
            l_node->kv1    = *kv;
            l_node->child0 = child0;
            l_node->child1 = child1;
        }
        else if( kv->key > node->kv2.key )
        {
            root_kv        = l_node->kv2;
            r_node->kv1    = *kv;
            r_node->child0 = child0;
            r_node->child1 = child1;
        }
        else
        {
            root_kv        = *kv;
            r_node->kv1    = l_node->kv2;
            r_node->child1 = l_node->child2;
            r_node->child0 = child1;
            l_node->child1 = child0;
        }
        r_node->child2 = NULL;
        l_node->child2 = NULL;

        btree_node_vd_s_set_parent_child0( r_node );
        btree_node_vd_s_set_parent_child1( r_node );
        btree_node_vd_s_set_parent_child0( l_node );
        btree_node_vd_s_set_parent_child1( l_node );

        if( l_node->parent )
        {
            btree_vd_s_push( o, l_node->parent, &root_kv, l_node, r_node );
        }
        else
        {
            o->root = btree_vd_s_new_node( o );
            o->root->kv1    = root_kv;
            o->root->child0 = l_node;
            o->root->child1 = r_node;
            l_node->parent  = o->root;
            r_node->parent  = o->root;
        }
    }
    else
    {
        if( kv->key < node->kv1.key )
        {
            node->kv2    = node->kv1;
            node->kv1    = *kv;
            node->child2 = node->child1;
            node->child1 = child1;
            node->child0 = child0;
            btree_node_vd_s_set_parent_child0( node );
            btree_node_vd_s_set_parent_child1( node );
            btree_node_vd_s_set_parent_child2( node );
        }
        else
        {
            node->kv2    = *kv;
            node->child2 = child1;
            node->child1 = child0;
            btree_node_vd_s_set_parent_child1( node );
            btree_node_vd_s_set_parent_child2( node );
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------

// Recursively pulls an element from a non-leaf into an empty child node
void btree_vd_s_pull( btree_vd_s* o, btree_node_vd_s* node )
{
    if( btree_node_vd_s_is_empty( node->child0 ) )
    {
        if( btree_node_vd_s_is_full( node->child1 ) )
        {
            node->child0->kv1    = node->kv1;
            node->child0->child1 = node->child1->child0;
            btree_node_vd_s_set_parent_child1( node->child0 );
            node->kv1            = node->child1->kv1;
            node->child1->kv1    = node->child1->kv2;
            node->child1->child0 = node->child1->child1;
            node->child1->child1 = node->child1->child2;
            node->child1->child2 = NULL;
        }
        else if( btree_node_vd_s_is_full( node ) )
        {
            node->child1->kv2    = node->child1->kv1;
            node->child1->kv1    = node->kv1;
            node->child1->child2 = node->child1->child1;
            node->child1->child1 = node->child1->child0;
            node->child1->child0 = node->child0->child0;
            btree_node_vd_s_set_parent_child0( node->child1 );
            btree_vd_s_delete_node( o, node->child0 );
            node->kv1    = node->kv2;
            node->child0 = node->child1;
            node->child1 = node->child2;
            node->child2 = NULL;
        }
        else
        {
            node->child1->kv2    = node->child1->kv1;
            node->child1->kv1    = node->kv1;
            node->child1->child2 = node->child1->child1;
            node->child1->child1 = node->child1->child0;
            node->child1->child0 = node->child0->child0;
            btree_node_vd_s_set_parent_child0( node->child1 );
            btree_vd_s_delete_node( o, node->child0 );
            node->child0 = node->child1;
            node->child1 = node->child2 = NULL;
            if( node->parent )
            {
                btree_vd_s_pull( o, node->parent );
            }
            else
            {
                o->root = node->child0;
                o->root->parent = NULL;
                btree_vd_s_delete_node( o, node );
            }
        }
    }
    else if( btree_node_vd_s_is_empty( node->child1 ) )
    {
        if( btree_node_vd_s_is_full( node->child0 ) )
        {
            node->child1->kv1    = node->kv1;
            node->child1->child1 = node->child1->child0;
            node->child1->child0 = node->child0->child2;
            btree_node_vd_s_set_parent_child0( node->child1 );
            node->kv1            = node->child0->kv2;
            node->child0->child2 = NULL;
        }
        else if( btree_node_vd_s_is_full( node ) )
        {
            node->child0->kv2    = node->kv1;
            node->child0->child2 = node->child1->child0;
            btree_node_vd_s_set_parent_child2( node->child0 );
            btree_vd_s_delete_node( o, node->child1 );
            node->kv1    = node->kv2;
            node->child1 = node->child2;
            node->child2 = NULL;
        }
        else
        {
            node->child0->kv2    = node->kv1;
            node->child0->child2 = node->child1->child0;
            btree_node_vd_s_set_parent_child2( node->child0 );
            btree_vd_s_delete_node( o, node->child1 );
            node->child1 = node->child2 = NULL;
            if( node->parent )
            {
                btree_vd_s_pull( o, node->parent );
            }
            else
            {
                o->root = node->child0;
                o->root->parent = NULL;
                btree_vd_s_delete_node( o, node );
            }
        }
    }
    else // node->child2 is empty
    {
        if( btree_node_vd_s_is_full( node ) )
        {
            if( btree_node_vd_s_is_full( node->child1 ) )
            {
                node->child2->kv1 = node->kv2;
                node->child2->child1 = node->child2->child0;
                node->child2->child0 = node->child1->child2;
                btree_node_vd_s_set_parent_child0( node->child2 );
                node->kv2            = node->child1->kv2;
                node->child1->child2 = NULL;
            }
            else
            {
                node->child1->kv2    = node->kv2;
                node->child1->child2 = node->child2->child0;
                btree_node_vd_s_set_parent_child2( node->child1 );
                btree_vd_s_delete_node( o, node->child2 );
                node->child2         = NULL;
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------

bool btree_vd_s_exists( const btree_vd_s* o, btree_vd_key_t key )
{
    if( !o )    return false;
    btree_node_vd_s* node = btree_node_vd_s_find( o->root, key );
    if( !node ) return false;
    if( node->kv1.key == key ) return true;
    if( node->child2 && node->kv2.key == key ) return true;
    return false;
}

// ---------------------------------------------------------------------------------------------------------------------

btree_vd_key_t btree_vd_s_largest_below_equal( const btree_vd_s* o, btree_vd_key_t key )
{
    btree_vd_key_t ret = btree_node_vd_s_largest_below_equal( o->root, key );

    // for the (hypothetical) case where ( NULL != (vp_t)0 )
    return ( ret == 0 ) ? NULL : ret;
}

// ---------------------------------------------------------------------------------------------------------------------

int btree_vd_s_set( btree_vd_s* o, btree_vd_key_t key )
{
    if( !o ) return -2;
    if( !o->root )
    {
        o->root = btree_vd_s_new_node( o );
        o->root->child0 = o->root->child1 = BNUL_VP;
        o->root->child2 = NULL;
        o->root->kv1.key = key;
        return 1;
    }

    btree_node_vd_s* node = btree_node_vd_s_find( o->root, key );
    if( !node ) return -2;

    if( node->kv1.key == key )
    {
        return 0;
    }
    else if( node->child2 && node->kv2.key == key )
    {
        return 0;
    }
    else
    {
        btree_vd_kv_s kv = { key };
        btree_vd_s_push( o, node, &kv, BNUL_VP, BNUL_VP );
        return 1;
    }
}

// ---------------------------------------------------------------------------------------------------------------------

int btree_vd_s_remove( btree_vd_s* o, btree_vd_key_t key )
{
    if( !o       ) return -1;
    if( !o->root ) return  0;
    btree_node_vd_s* node = btree_node_vd_s_find( o->root, key );
    if( !node    ) return -1;

    if( node->kv1.key == key )
    {
        if( !btree_node_vd_s_is_leaf( node ) )
        {
            btree_node_vd_s* trace = node->child0;
            while( !btree_node_vd_s_is_leaf( trace ) ) trace = ( trace->child2 ) ? trace->child2 : trace->child1;
            if( btree_node_vd_s_is_full( trace ) )
            {
                node->kv1   = trace->kv2;
                trace->child2 = NULL;
            }
            else
            {
                node->kv1 = trace->kv1;
                trace->child1 = trace->child2 = NULL;
                btree_vd_s_pull( o, trace->parent );
            }
        }
        else if( btree_node_vd_s_is_full( node ) )
        {
            node->kv1 = node->kv2;
            node->child2 = NULL;
        }
        else
        {
            node->child1 = node->child2 = NULL;
            if( node->parent )
            {
                btree_vd_s_pull( o, node->parent );
            }
            else
            {
                btree_vd_s_delete_node( o, node );
                o->root = NULL;
            }
        }
        return 1;
    }

    if( node->kv2.key == key )
    {
        if( !btree_node_vd_s_is_leaf( node ) )
        {
            btree_node_vd_s* trace = ( node->child2 ) ? node->child2 : node->child1;
            while( !btree_node_vd_s_is_leaf( trace ) ) trace = trace->child0;
            if( btree_node_vd_s_is_full( trace ) )
            {
                node->kv2     = trace->kv1;
                trace->kv1    = trace->kv2;
                trace->child2 = NULL;
            }
            else
            {
                node->kv2   = trace->kv1;
                trace->child1 = trace->child2 = NULL;
                btree_vd_s_pull( o, trace->parent );
            }
        }
        else if( btree_node_vd_s_is_full( node ) )
        {
            node->child2 = NULL;
        }
        else
        {
            node->child1 = node->child2 = NULL;
            if( node->parent )
            {
                btree_vd_s_pull( o, node->parent );
            }
            else
            {
                btree_vd_s_delete_node( o, node );
                o->root = NULL;
            }
        }
        return 1;
    }
    return 0;
}

// ---------------------------------------------------------------------------------------------------------------------

void btree_vd_s_run( const btree_vd_s* o, void(*func)( void* arg, btree_vd_key_t key ), void* arg )
{
    btree_node_vd_s_run( o->root, func, arg );
}

// ---------------------------------------------------------------------------------------------------------------------

size_t btree_vd_s_count( const btree_vd_s* o, bool(*func)( void* arg, btree_vd_key_t key ), void* arg )
{
    return btree_node_vd_s_count( o->root, func, arg );
}

// ---------------------------------------------------------------------------------------------------------------------

size_t btree_vd_s_depth( const btree_vd_s* o )
{
    return btree_node_vd_s_depth( o->root );
}

// ---------------------------------------------------------------------------------------------------------------------

void print_btree_vd_s_status( btree_vd_s* o )
{
    size_t blocks = 0;
    size_t nodes = 0;
    size_t deleted_nodes = 0;
    if( o->chain_beg )
    {
        btree_node_vd_s* chain_beg = o->chain_beg;
        while( chain_beg )
        {
            chain_beg = *( btree_node_vd_s** )( chain_beg + o->block_size );
            blocks++;
        }
        nodes = blocks * o->block_size - ( o->chain_end - o->chain_ins );
    }
    if( o->del_chain )
    {
        btree_node_vd_s* del_chain = o->del_chain;
        while( del_chain )
        {
            del_chain = del_chain->parent;
            deleted_nodes++;
        }
    }

    size_t used_nodes = nodes - deleted_nodes;
    printf( "keys ........... %zu\n", btree_node_vd_s_keys( o->root ) );
    printf( "nodes .......... %zu\n", used_nodes );
    printf( "keys/nodes ..... %5.4f\n", used_nodes > 0 ? ( double )( btree_node_vd_s_keys( o->root ) ) / used_nodes : 0 );
    printf( "depth .......... %zu\n", btree_node_vd_s_depth( o->root ) );
    printf( "block size ..... %zu\n", o->block_size );
    printf( "blocks ......... %zu\n", blocks );
    printf( "deleted nodes .. %zu\n", deleted_nodes );
}

// ---------------------------------------------------------------------------------------------------------------------

