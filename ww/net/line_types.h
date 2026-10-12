#pragma once

/* Shared line layout for inline line accessors and tunnel dispatch. */

#include "address_context.h"
#include "generic_pool.h"
#include "objects/user_handle.h"
#include "wlibc.h"
#include "worker.h"

typedef atomic_u32_t line_refc_t;
#define LINE_REFC_MAX UINT32_MAX

enum
{
    kLineMaxUsers = 4
};

typedef struct line_user_credentials_s
{
    char *username;
    char *password;
} line_user_credentials_t;

typedef struct line_user_auth_s
{
    bool                    has_handle;
    bool                    has_credentials;
    user_handle_t           handle;
    line_user_credentials_t credentials;
} line_user_auth_t;

/*
    The line struct represents a connection, it has two ends ( Down-end < --------- > Up-end)

    A blocked write on the Down-end emits advisory Pause toward the Up-end source, and vice versa.
    There is no global paused state here; receivers keep their own limits and endpoint producer control.

    each context creation will increase refc on the line, so the line will never gets destroyed
    before the contexts that reference it. Every decrement is an acquire-release operation, so
    the final releaser acquires that release sequence before reading or reclaiming line state. This
    reference-count edge is what publishes owner teardown to a foreign final releaser.

    line holds all the info such as dest and src contexts, it also contains each tunnel per connection state
    in tunnels_line_state[(tunnel_index)]

    a line only belongs to 1 thread, but it can cross the threads (if actually needed) using pipe line, easily
*/

typedef struct routing_context_s
{
    address_context_t src_ctx;
    address_context_t dest_ctx;
    uint16_t          local_listener_port;
    uint16_t          peer_source_port;

} routing_context_t;

typedef struct line_s
{
    line_refc_t       refc;
    bool              alive;
    wid_t             wid;
    uint64_t          active_tunnels_mask; // One bit per chain index; cleared bits permanently bypass callbacks.
    line_user_auth_t  user_auths[kLineMaxUsers];
    uint8_t           user_count;
    uint8_t           established : 1;
    uint8_t           recalculate_checksum : 1; // used for packet tunnels
    uint8_t           prefer_ordinary_read_u : 1;
    uint8_t           prefer_ordinary_read_d : 1;
    routing_context_t routing_context;

    generic_pool_t **pools;

    MSVC_ATTR_ALIGNED_LINE_CACHE uintptr_t *tunnels_line_state[] GNU_ATTR_ALIGNED_LINE_CACHE;

} line_t;
