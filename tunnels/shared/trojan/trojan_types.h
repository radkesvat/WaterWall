#pragma once

#include "basic_types.h"
#include "sha2.h"

typedef unsigned char sha224_t[SHA224_DIGEST_SIZE];
typedef unsigned char sha224_hex_t[SHA224_DIGEST_SIZE * 2];

typedef struct trojan_user_s
{
    struct user_s user;
    sha224_t      sha224_of_user_uid;
    sha224_hex_t  hexed_sha224_of_user_uid;
    hash_t        hash_of_hexed_sha224_of_user_uid;

} trojan_user_t;
