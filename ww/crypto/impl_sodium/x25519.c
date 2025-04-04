#include "wcrypto.h"
#include "wlibc.h"

#include "sodium.h"

// Function to perform X25519 scalar multiplication
int performX25519(unsigned char out[32], const unsigned char scalar[32], const unsigned char point[32])
{
    assert(sodium_init() != -1 && "libsodium must be initialized before calling this function");

    // This dose clamp the base point 
    // Perform the scalar multiplication using crypto_scalarmult
    if (0 != crypto_scalarmult(out, scalar, point))
    {
        // Scalar multiplication failed
        return -1;
    }
    // Success
    return 0;
}
