#pragma once

#include "basic_types.h"
#include "sha2.h"

typedef unsigned char sha224_t[SHA224_DIGEST_SIZE];
typedef unsigned char sha224_hex_t[SHA224_DIGEST_SIZE*2];

typedef struct trojan_user_s
{

    struct user_s user;
    sha224_t hash_user;
    sha224_hex_t hash_hexed_user;
    hash_t komihash_of_hex;

} trojan_user_t;
