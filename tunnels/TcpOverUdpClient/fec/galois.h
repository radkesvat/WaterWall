//
// Created by 理 傅 on 2016/12/30.
//

#ifndef KCP_GALOIS_H
#define KCP_GALOIS_H

typedef unsigned char byte;

byte galAdd(byte a, byte b);

byte galSub(byte a, byte b);

// galMultiply multiplies to elements of the field.
// Uses lookup table ~40% faster
byte galMultiply(byte a, byte b);

// galDivide is inverse of galMultiply.
byte galDivide(byte a, byte b);

// Computes a**n.
//
// The result will be the same as multiplying a times itself n times.
byte galExp(byte a, byte b);

#endif //KCP_GALOIS_H
