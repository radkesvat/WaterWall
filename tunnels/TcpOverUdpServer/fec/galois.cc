//
// Created by 理 傅 on 2016/12/30.
//

#include <stdexcept>
#include "galois.h"

extern const int fieldSize;
extern byte mulTable[256][256];
extern const byte logTable[];
extern byte expTable[];

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