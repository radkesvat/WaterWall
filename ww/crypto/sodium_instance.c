#include "sodium_instance.h"
#include "sodium.h"

int initSodium(void)
{
    // Ensure libsodium is initialized
    if (sodium_init() < 0) {
        return -1;
    }
    return 1;
}

