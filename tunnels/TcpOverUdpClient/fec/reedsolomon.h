//
// Created by 理 傅 on 2017/1/1.
//

#ifndef KCP_REEDSOLOMON_H
#define KCP_REEDSOLOMON_H

#include "matrix.h"
#include "inversion_tree.h"
#include "galois.h"

class ReedSolomon {
public:
    ReedSolomon() = default;

    ReedSolomon(int dataShards, int parityShards);

    // New creates a new encoder and initializes it to
    // the number of data shards and parity shards that
    // you want to use. You can reuse this encoder.
    // Note that the maximum number of data shards is 256.
    static ReedSolomon New(int dataShards, int parityShards);

    // Encodes parity for a set of data shards.
    // An array 'shards' containing data shards followed by parity shards.
    // The number of shards must match the number given to New.
    // Each shard is a byte array, and they must all be the same empty.
    // The parity shards will always be overwritten and the data shards
    // will remain the same.
    void Encode(std::vector<row_type> &shards);

    // Reconstruct will recreate the missing shards, if possible.
    //
    // Given a list of shards, some of which contain data, fills in the
    // ones that don't have data.
    //
    // The length of the array must be equal to Shards.
    // You indicate that a shard is missing by setting it to nil.
    //
    // If there are too few shards to reconstruct the missing
    // ones, ErrTooFewShards will be returned.
    //
    // The reconstructed shard set is complete, but integrity is not verified.
    // Use the Verify function to check if data set is ok.
    void Reconstruct(std::vector<row_type> &shards);

private:
    int m_dataShards;  // Number of data shards, should not be modified.
    int m_parityShards; // Number of parity shards, should not be modified.
    int m_totalShards; // Total number of shards. Calculated, and should not be modified.

    matrix m;
    inversionTree tree;
    std::vector<row_type> parity;

    int shardSize(std::vector<row_type> &shards);


    // Multiplies a subset of rows from a coding matrix by a full set of
    // Input shards to produce some output shards.
    // 'matrixRows' is The rows from the matrix to use.
    // 'inputs' An array of byte arrays, each of which is one Input shard.
    // The number of inputs used is determined by the length of each matrix row.
    // outputs Byte arrays where the computed shards are stored.
    // The number of outputs computed, and the
    // number of matrix rows used, is determined by
    // outputCount, which is the number of outputs to compute.
    void
    codeSomeShards(std::vector<row_type> &matrixRows, std::vector<row_type> &inputs, std::vector<row_type> &outputs,
                   int outputCount);

    // checkShards will check if shards are the same size
    // or 0, if allowed. An error is returned if this fails.
    // An error is also returned if all shards are size 0.
    void checkShards(std::vector<row_type> &shards, bool nilok) ;
};


#endif //KCP_REEDSOLOMON_H
