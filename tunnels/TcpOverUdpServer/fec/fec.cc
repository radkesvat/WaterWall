//
// Created by 理 傅 on 2017/1/2.
//

#include <err.h>
#include <sys/time.h>
#include <iostream>
#include <stdexcept>
#include "fec.h"
#include "sess.h"
#include "encoding.h"

FEC::FEC(ReedSolomon enc) :enc(enc) {}

FEC
FEC::New(int rxlimit, int dataShards, int parityShards)  {
    if (dataShards <= 0 || parityShards <= 0) {
        throw std::invalid_argument("invalid arguments");
    }

    if (rxlimit < dataShards+parityShards) {
        throw std::invalid_argument("invalid arguments");
    }

    FEC fec(ReedSolomon::New(dataShards, parityShards));
    fec.rxlimit = rxlimit;
    fec.dataShards = dataShards;
    fec.parityShards = parityShards;
    fec.totalShards = dataShards + parityShards;
    fec.paws = (0xffffffff/uint32_t(fec.totalShards) - 1) * uint32_t(fec.totalShards);

    return fec;
}

fecPacket
FEC::Decode(byte *data, size_t sz) {
    fecPacket pkt;
    data = decode32u(data, &pkt.seqid);
    data = decode16u(data, &pkt.flag);
    struct timeval time;
    gettimeofday(&time, NULL);
    pkt.ts = uint32_t(time.tv_sec * 1000 + time.tv_usec/1000);
    pkt.data = std::make_shared<std::vector<byte>>(data, data+sz - fecHeaderSize);
    return pkt;
}

void
FEC::MarkData(byte *data, uint16_t sz) {
    data = encode32u(data,this->next);
    data = encode16u(data,typeData);
    encode16u(data,static_cast<uint16_t>(sz + 2)); // including size itself
    this->next++;
}

void
FEC::MarkFEC(byte *data) {
    data = encode32u(data,this->next);
    encode16u(data,typeFEC);
    this->next++;
    if (this->next >= this->paws) { // paws would only occurs in MarkFEC
        this->next = 0;
    }
}

std::vector<row_type>
FEC::Input(fecPacket &pkt) {
    std::vector<row_type> recovered;

    uint32_t now = currentMs();
    if (now-lastCheck >= fecExpire) {
        for (auto it = rx.begin();it !=rx.end();) {
            if (now - it->ts > fecExpire) {
                it = rx.erase(it);
            } else {
                it++;
            }
        }
        lastCheck = now;
    }


    // insertion
    auto n = this->rx.size() -1;
    int insertIdx = 0;
    for (int i=n;i>=0;i--) {
        if (pkt.seqid == rx[i].seqid) {
            return recovered;
        } else if (pkt.seqid > rx[i].seqid) {
            insertIdx = i + 1;
            break;
        }
    }
    // insert into ordered rx queue
    rx.insert(rx.begin()+insertIdx, pkt);

    // shard range for current packet
    auto shardBegin = pkt.seqid - pkt.seqid%totalShards;
    auto shardEnd = shardBegin + totalShards - 1;

    // max search range in ordered queue for current shard
    auto searchBegin = insertIdx - int(pkt.seqid%totalShards);
    if (searchBegin < 0) {
        searchBegin = 0;
    }

    auto searchEnd = searchBegin + totalShards - 1;
    if (searchEnd >= rx.size()) {
        searchEnd = rx.size()-1;
    }

    if (searchEnd > searchBegin && searchEnd-searchBegin+1 >= dataShards) {
        int numshard = 0;
        int numDataShard = 0;
        int first = 0;
        size_t maxlen = 0;

        std::vector<row_type> shardVec(totalShards);
        std::vector<bool> shardflag(totalShards, false);

        for (auto i = searchBegin; i <= searchEnd; i++) {
            auto seqid = rx[i].seqid;
            if (seqid > shardEnd) {
                break;
            } else if (seqid >= shardBegin) {
                shardVec[seqid%totalShards] = rx[i].data;
                shardflag[seqid%totalShards] = true;
                numshard++;
                if (rx[i].flag == typeData) {
                    numDataShard++;
                }
                if (numshard == 1) {
                    first = i;
                }
                if (rx[i].data->size() > maxlen) {
                    maxlen = rx[i].data->size();
                }
            }
        }

        if (numDataShard == dataShards) { // no lost
            rx.erase(rx.begin()+first, rx.begin() + first+numshard);
        } else if (numshard >= dataShards) { // recoverable
            // equally resized
            for (int i=0;i<shardVec.size();i++) {
                if (shardVec[i] != nullptr) {
                    shardVec[i]->resize(maxlen, 0);
                }
            }

            // reconstruct shards
            enc.Reconstruct(shardVec);
            for (int k =0;k<dataShards;k++) {
                if (!shardflag[k]) {
                    recovered.push_back(shardVec[k]);
                }
            }
            rx.erase(rx.begin()+first, rx.begin() + first+numshard);
        }
    }

    // keep rxlimit
    if (rx.size() > rxlimit) {
        rx.erase(rx.begin());
    }

    return recovered;
}


void FEC::Encode(std::vector<row_type> &shards) {
    // resize elements with 0 appending
    size_t max = 0;
    for (int i = 0;i<dataShards;i++) {
        if (shards[i]->size() > max) {
            max = shards[i]->size();
        }
    }

    for ( auto &s : shards) {
        if (s == nullptr) {
            s = std::make_shared<std::vector<byte>>(max);
        } else {
            s->resize(max, 0);
        }
    }

    enc.Encode(shards);
}
