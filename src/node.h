#pragma once


#include "common_types.h"
#include "cJSON.h"

#define i_type map_nodes
#define i_key hash_t
#define i_val node_t*

#include "stc/hmap.h"


typedef struct node_s{
    char* name;
    hash_t ident;
    char* type_name;
    hash_t type_ident;
    cJSON* settings;
    hash_t next;
    size_t refrenced;
    size_t version;
    //------------
    unsigned listener:1;
    unsigned sender:1;

} node_t;


struct nodes_file{
    map_nodes map;
    
} 