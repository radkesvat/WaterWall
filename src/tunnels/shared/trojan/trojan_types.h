#pragma once

#include "common_types.h"
#include "sha2.h"

typedef char sha224_t[SHA224_DIGEST_SIZE];

typedef struct trojan_user_s
{

    struct user_s user;
    sha224_t user_hash;

} trojan_user_t;
