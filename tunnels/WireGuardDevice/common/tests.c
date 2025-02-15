#include "structure.h"

// Helper function to compare results
static inline bool compareBuffers(const uint8_t *a, const uint8_t *b, size_t len)
{
    return wCryptoEqual(a, b, len);
}

// Test BLAKE2s
static void testBlake2s(void)
{
    {
        const uint8_t input[]      = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
        uint8_t       output[32]   = {0};
        uint8_t       expected[32] = {0x60, 0xe2, 0x6d, 0xae, 0xf3, 0x27, 0xef, 0xc0, 0x2e, 0xc3, 0x35,
                                      0xe2, 0xa0, 0x25, 0xd2, 0xd0, 0x16, 0xeb, 0x42, 0x06, 0xf8, 0x72,
                                      0x77, 0xf5, 0x2d, 0x38, 0xd1, 0x98, 0x8b, 0x78, 0xcd, 0x36};
        // correct hash value

        size_t input_len = sizeof(input) - 1; // Exclude null terminator

        // Known output test
        if (0 != blake2s(output, sizeof(output), NULL, 0, input, input_len))
        {
            printError("BLAKE2s failed\n");
            exit(1);
        }

        printHex("BLAKE2s Output", output, sizeof(output));
        printHex("Expected Output", expected, sizeof(expected));

        if (! compareBuffers(output, expected, sizeof(output)))
        {
            printError("BLAKE2s known output test failed\n");
            exit(1);
        }
        else
        {
            printDebug("BLAKE2s known output test passed\n");
        }
    }
    {
        const uint8_t input[]      = "Salam farmande! seyed ali dahe 80 hasho fara khande!";
        const uint8_t key[]        = {0x00, 0x01, 0x02, 0x03}; // Example key
        uint8_t       output[32]   = {0};
        uint8_t       expected[32] = {0xf5, 0xae, 0x22, 0xd5, 0xd5, 0x5f, 0xb3, 0x1e, 0x5c, 0xf2, 0x61,
                                      0x99, 0x9c, 0x2f, 0x5d, 0x88, 0x95, 0xb3, 0xf2, 0x02, 0x32, 0x57,
                                      0x19, 0x61, 0x43, 0x9e, 0xcf, 0x58, 0x6e, 0x58, 0x48, 0xed

        };
        // correct hash value

        size_t input_len = sizeof(input) - 1; // Exclude null terminator
        size_t key_len   = sizeof(key);

        // Known output test
        if (0 != blake2s(output, sizeof(output), key, key_len, input, input_len))
        {
            printError("BLAKE2s failed\n");
            exit(1);
        }

        printHex("BLAKE2s Output", output, sizeof(output));
        printHex("Expected Output", expected, sizeof(expected));

        if (! compareBuffers(output, expected, sizeof(output)))
        {
            printError("BLAKE2s known output test failed\n");
            exit(1);
        }
        else
        {
            printDebug("BLAKE2s known output test passed\n");
        }
    }
}

// Test X25519
static void testX25519(void)
{ // Example private key
    uint8_t scalar[32] = {0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1,
                          0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0,
                          0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a

    };

    // Example public key
    uint8_t point[32] = {0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61,
                         0xc2, 0xec, 0xe4, 0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78,
                         0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f

    };

    uint8_t shared_secret[32] = {0};
    uint8_t expected[32]      = {0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b,
                                 0xf4, 0x80, 0x35, 0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1,
                                 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42};

    if (0 != performX25519(shared_secret, scalar, point))
    {
        printError("X25519 failed\n");
        exit(1);
    }

    printHex("X25519 Shared Secret", shared_secret, sizeof(shared_secret));
    printHex("Expected Shared Secret", expected, sizeof(expected));

    if (! compareBuffers(shared_secret, expected, sizeof(shared_secret)))
    {
        printError("X25519 known output test failed\n");
        exit(1);
    }
    else
    {
        printDebug("X25519 known output test passed\n");
    }
}

// Test ChaCha20-Poly1305 Encrypt/Decrypt
static void testChaCha20Poly1305(void)
{
    const uint8_t plaintext[] = "This is a secret message!";
    const uint8_t ad[]        = "Additional authenticated data";
    const uint8_t key[32]     = {0x00}; // Example key
    const uint8_t nonce[12]   = {
        0, 0, 0, 0, 88, 90, 07, 1, 2, 3, 4, 8,
    }; // Example nonce
    uint8_t ciphertext[sizeof(plaintext) + 16] = {0};
    uint8_t decrypted[sizeof(plaintext)]       = {0};
    uint8_t expected[sizeof(plaintext) + 16]   = {0x88, 0x10, 0xcc, 0x6b, 0xc6, 0x12, 0xb2, 0xe3, 0x71, 0xf9, 0x9a,
                                                  0x1e, 0xed, 0x2b, 0x87, 0x27, 0x50, 0x1d, 0x2a, 0xba, 0xf0, 0x77,
                                                  0x03, 0xb6, 0x63, 0x16, 0x50, 0xd2, 0x52, 0x5b, 0x16, 0xb7, 0x18,
                                                  0xd8, 0x8e, 0x24, 0x51, 0x67, 0x41, 0xb7, 0x1e, 0x00};

    size_t plaintext_len = sizeof(plaintext) - 1; // Exclude null terminator
    size_t ad_len        = sizeof(ad) - 1;

    // Known output test
    if (0 != chacha20poly1305Encrypt(ciphertext, plaintext, plaintext_len, ad, ad_len, nonce, key))
    {
        printError("ChaCha20-Poly1305 encryption failed\n");
        exit(1);
    }

    printHex("ChaCha20-Poly1305 Ciphertext", ciphertext, sizeof(ciphertext));
    printHex("Expected Ciphertext", expected, sizeof(expected));

    if (! compareBuffers(ciphertext, expected, sizeof(ciphertext)))
    {
        printError("ChaCha20-Poly1305 known output test failed\n");
        exit(1);
    }
    else
    {
        printDebug("ChaCha20-Poly1305 known output test passed\n");
    }

    // Round-trip test
    if (0 != chacha20poly1305Decrypt(decrypted, ciphertext, sizeof(ciphertext) - 1, ad, ad_len, nonce, key))
    {
        printError("ChaCha20-Poly1305 decryption failed\n");
        exit(1);
    }

    if (! compareBuffers(decrypted, plaintext, plaintext_len))
    {
        printError("ChaCha20-Poly1305 round-trip test failed\n");
        exit(1);
    }
    else
    {
        printDebug("ChaCha20-Poly1305 round-trip test passed\n");
    }
}

// Test XChaCha20-Poly1305 Encrypt/Decrypt
static void testXChaCha20Poly1305(void)
{
    const uint8_t plaintext[]                        = "This is a secret message!";
    const uint8_t ad[]                               = "Additional authenticated data";
    const uint8_t key[32]                            = {0x00}; // Example key
    const uint8_t nonce[24]                          = {0x01}; // Example nonce
    uint8_t       ciphertext[sizeof(plaintext) + 16] = {0};
    uint8_t       decrypted[sizeof(plaintext)]       = {0};
    uint8_t       expected[sizeof(plaintext) + 16]   = {

        0X3e, 0x51, 0x7a, 0xb2, 0xdf, 0x97, 0x45, 0x79, 0x36, 0xe7, 0x86, 0xf3, 0x96, 0x0c,
        0xda, 0x04, 0x3c, 0x9b, 0x3f, 0x38, 0xdd, 0xce, 0x59, 0x2b, 0x49, 0xd4, 0x0f, 0x6e,
        0x19, 0x66, 0xb7, 0x36, 0x32, 0x87, 0x5a, 0x73, 0x5f, 0x00, 0xb1, 0xb7, 0x3e, 0x00};

    size_t plaintext_len = sizeof(plaintext) - 1; // Exclude null terminator
    size_t ad_len        = sizeof(ad) - 1;

    // Known output test
    if (0 != xchacha20poly1305Encrypt(ciphertext, plaintext, plaintext_len, ad, ad_len, nonce, key))
    {
        printError("XChaCha20-Poly1305 encryption failed\n");
        exit(1);
    }

    printHex("XChaCha20-Poly1305 Ciphertext", ciphertext, sizeof(ciphertext));
    printHex("Expected Ciphertext", expected, sizeof(expected));

    if (! compareBuffers(ciphertext, expected, sizeof(ciphertext)))
    {
        printError("XChaCha20-Poly1305 known output test failed\n");
        exit(1);
    }
    else
    {
        printDebug("XChaCha20-Poly1305 known output test passed\n");
    }

    // Round-trip test
    if (0 != xchacha20poly1305Decrypt(decrypted, ciphertext, sizeof(ciphertext) - 1, ad, ad_len, nonce, key))
    {
        printError("XChaCha20-Poly1305 decryption failed\n");
        exit(1);
    }

    if (! compareBuffers(decrypted, plaintext, plaintext_len))
    {
        printError("XChaCha20-Poly1305 round-trip test failed\n");
        exit(1);
    }
    else
    {
        printDebug("XChaCha20-Poly1305 round-trip test passed\n");
    }
}

void testWireGuardImpl(void)
{
    testBlake2s();
    testX25519();
    testChaCha20Poly1305();
    testXChaCha20Poly1305();
}
