//
// Created by 理 傅 on 2016/12/30.
//

#include <stdexcept>

#include "galois.h"

const int fieldSize = 256;
byte      mulTable[256][256];
byte      logTable[256];
byte      expTable[512];

namespace
{

struct galois_tables_initializer_t
{
    galois_tables_initializer_t()
    {
        int value = 1;
        for (int i = 0; i < 255; ++i)
        {
            expTable[i]     = (byte) value;
            logTable[value] = (byte) i;

            value <<= 1;
            if ((value & 0x100) != 0)
            {
                value ^= 0x11d;
            }
        }

        for (int i = 255; i < 512; ++i)
        {
            expTable[i] = expTable[i - 255];
        }

        for (int a = 0; a < 256; ++a)
        {
            for (int b = 0; b < 256; ++b)
            {
                if (a == 0 || b == 0)
                {
                    mulTable[a][b] = 0;
                }
                else
                {
                    mulTable[a][b] = expTable[(int) logTable[a] + (int) logTable[b]];
                }
            }
        }
    }
};

galois_tables_initializer_t galois_tables_initializer;

} // namespace

byte galAdd(byte a, byte b) {
    return a ^ b;
}

byte galSub(byte a, byte b) {
    return a ^ b;
}

byte galMultiply(byte a, byte b) {
    return mulTable[a][b];
}

byte galDivide(byte a, byte b) {
    if (a == 0) {
        return 0;
    }

    if (b == 0) {
        throw std::invalid_argument("Argument 'divisor' is 0");
    }

    int logA = logTable[a];
    int logB = logTable[b];
    int logResult = logA - logB;
    if (logResult < 0) {
        logResult += 255;
    }
    return expTable[logResult];
}

byte galExp(byte a, byte n) {
    if (n == 0) {
        return 1;
    }
    if (a == 0) {
        return 0;
    }

    int logA = logTable[a];
    int logResult = logA * n;
    while (logResult >= 255) {
        logResult -= 255;
    }
    return expTable[logResult];
}
