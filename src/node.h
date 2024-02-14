#pragma once

#include "common_types.h"
#include "cJSON.h"

typedef struct node_s
{
    char *name;
    hash_t ident;
    char *type_name;
    hash_t type_ident;
    char *next_name;
    hash_t next_ident;

    cJSON *settings;

    size_t refrenced;
    size_t version;
    //------------
    unsigned listener : 1;
    unsigned sender : 1;

} node_t;

struct nodes_file
{
    char *name;
    char *author;
    size_t minimum_version;
    bool encrypted;
    cJSON *nodes;
};

#define i_type node_map_t
#define i_key hash_t
#define i_val node_t *

#include "stc/hmap.h"

#define i_type node_array_t
#define i_key hash_t

#include "stc/vec.h"