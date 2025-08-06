//
// Created by 理 傅 on 2017/1/2.
//

#ifndef KCP_FEC_H
#define KCP_FEC_H


#include <vector>
#include <stdint.h>
#include <memory>
#include "reedsolomon.h"

const size_t fecHeaderSize = 6;
const size_t fecHeaderSizePlus2{fecHeaderSize + 2};
const uint16_t typeData = 0xf1;
const uint16_t typeFEC = 0xf2;
const int fecExpire = 30000;

class fecPacket {
public:
    uint32_t seqid;
    uint16_t flag;
    row_type data;
    uint32_t ts;
};

class FEC {
public:
    FEC() = default;
    FEC(ReedSolomon enc);

    static FEC New(int rxlimit, int dataShards, int parityShards);

    inline bool isEnabled() { return dataShards > 0 && parityShards > 0 ; }

    // Input a FEC packet, and return recovered data if possible.
    std::vector<row_type> Input(fecPacket &pkt);

    // Calc Parity Shards
    void Encode(std::vector<row_type> &shards);

    // Decode a raw array into fecPacket
    static fecPacket Decode(byte *data, size_t sz);

    // Mark raw array as typeData, and write correct size.
    void MarkData(byte *data, uint16_t sz);

    // Mark raw array as typeFEC
    void MarkFEC(byte *data);
private:
    std::vector<fecPacket> rx; // ordered receive queue
    int rxlimit;  // queue empty limit
    int dataShards;
    int parityShards;
    int totalShards;
    uint32_t next{0}; // next seqid
    ReedSolomon enc;
    uint32_t paws;  // Protect Against Wrapped Sequence numbers
    uint32_t lastCheck{0};
};


#endif //KCP_FEC_H
