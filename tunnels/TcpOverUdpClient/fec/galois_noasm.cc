//
// Created by 理 傅 on 2016/12/30.
//

#include "galois_noasm.h"
#include "matrix.h"

extern const byte mulTable[256][256];

void galMulSlice(byte c, row_type in, row_type out) {
    for (int n=0;n<in->size();n++) {
        (*out)[n] = mulTable[c][(*in)[n]];
    }
}

void galMulSliceXor(byte c, row_type in, row_type out) {
    for (int n=0;n<in->size();n++) {
        (*out)[n] ^= mulTable[c][(*in)[n]];
    }
}
